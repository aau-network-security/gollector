package extract_features

import (
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"strings"
	"sync"

	"github.com/vbauerster/mpb/v4/decor"

	"github.com/vbauerster/mpb/v4"

	_ "github.com/lib/pq"

	"github.com/jinzhu/gorm"

	"github.com/google/certificate-transparency-go/x509"
	errs "github.com/pkg/errors"

	"github.com/rs/zerolog/log"

	"github.com/aau-network-security/gollector/store/models"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/go-pg/pg"
)

type ExtractFeatures struct {
	repo      string
	db        *pg.DB
	m         *sync.Mutex
	batchSize int
	inserts   []Features
	cache     cache
}

type cache struct {
	issuerIDs int
	issuers   map[string]*Issuer
}

func NewInserts() []Features {
	return []Features{}
}

type CertificateFeatures struct {
	id   uint // id from the DB
	cert *x509.Certificate
}

func (c *Config) Open() (*gorm.DB, error) {
	var err error
	if c.d == nil {
		c.d, err = gorm.Open("postgres", c.DSN())
	}
	return c.d, err
}

func (c *Config) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		c.Host, c.Port, c.User, c.Password, c.DBName)
}

type Config struct {
	Repo     string `yaml:"repository"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	DBName   string `yaml:"dbname"`

	d *gorm.DB
}

func readConfig(path string) (Config, error) {
	var conf Config
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return conf, errors.Wrap(err, "read config file")
	}
	if err := yaml.Unmarshal(f, &conf); err != nil {
		return conf, errors.Wrap(err, "unmarshal config file")
	}

	return conf, nil
}

func NexExtractFeatures(batchSize int) (*ExtractFeatures, error) {
	confFile := flag.String("config", "config.yml", "location of configuration file")
	flag.Parse()

	conf, err := readConfig(*confFile)
	if err != nil {
		log.Fatal().Msgf("error while reading configuration: %s", err)
	}

	pgOpts := pg.Options{
		User:     conf.User,
		Password: conf.Password,
		Addr:     fmt.Sprintf("%s:%d", conf.Host, conf.Port),
		Database: conf.DBName,
	}

	db := pg.Connect(&pgOpts)

	ef := ExtractFeatures{
		repo:      conf.Repo,
		db:        db,
		batchSize: batchSize,
		inserts:   NewInserts(),
		cache: cache{
			issuerIDs: 0,
			issuers:   map[string]*Issuer{},
		},
	}

	g, err := conf.Open()
	if err != nil {
		return nil, err
	}

	if err := g.AutoMigrate(Features{}).Error; err != nil {
		return nil, err
	}

	if err := g.AutoMigrate(Issuer{}).Error; err != nil {
		return nil, err
	}

	var issuers []*Issuer
	if err := ef.db.Model(&issuers).Order("id ASC").Select(); err != nil {
		return nil, err
	}
	for _, i := range issuers {
		ef.cache.issuers[i.Name] = i
	}

	ef.cache.issuerIDs = 1
	if len(issuers) > 1 {
		ef.cache.issuerIDs = issuers[len(issuers)-1].ID + 1
	}

	return &ef, nil
}

func (ef *ExtractFeatures) Start() error {

	if ef.repo == "bulldozer" {
		err := ef.StartBulldozer()
		return err
	}

	//Gollector
	count, err := ef.db.Model((*models.Certificate)(nil)).Count()
	if err != nil {
		return err
	}

	p := mpb.New(mpb.WithWidth(count))
	bar := p.AddBar(int64(count),
		mpb.PrependDecorators(
			// display our name with one space on the right
			decor.Name("Certificate Features", decor.WC{W: len("Certificate Features") + 1, C: decor.DidentRight}),
			// replace ETA decorator with "done" message, OnComplete event
			decor.OnComplete(
				decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 4}), "done",
			),
		),
		mpb.AppendDecorators(decor.Percentage()))

	for offset := 0; offset < count; offset += ef.batchSize {

		var DBcerts []*models.Certificate
		if err := ef.db.Model(&DBcerts).Order("id ASC").Offset(offset).Limit(ef.batchSize).Select(); err != nil {
			return err
		}
		var x509List []*CertificateFeatures
		for _, DBcert := range DBcerts {
			bar.Increment()
			cert, err := x509.ParseCertificate(DBcert.Raw)
			if err != nil {
				//log.Debug().Msgf("error parsing the certificate ID = %d", DBcert.ID)
				continue
			}
			x509List = append(x509List, &CertificateFeatures{
				id:   DBcert.ID,
				cert: cert,
			})
		}

		err = ef.getFeatures(x509List)
		if err != nil {
			log.Error().Msg("Error while getting the features")
		}
		err = ef.insert()
		if err != nil {
			log.Error().Msgf("%v", err)
		}
	}
	return nil
}

func (ef *ExtractFeatures) StartBulldozer() error {
	//Bulldozer
	count, err := ef.db.Model((*Cert)(nil)).Count()
	if err != nil {
		return err
	}

	p := mpb.New(mpb.WithWidth(count))
	bar := p.AddBar(int64(count),
		mpb.PrependDecorators(
			// display our name with one space on the right
			decor.Name("Certificate Features", decor.WC{W: len("Certificate Features") + 1, C: decor.DidentRight}),
			// replace ETA decorator with "done" message, OnComplete event
			decor.OnComplete(
				decor.AverageETA(decor.ET_STYLE_GO, decor.WC{W: 4}), "done",
			),
		),
		mpb.AppendDecorators(decor.Percentage()))

	for offset := 0; offset < count; offset += ef.batchSize {
		var DBcerts []*Cert
		if err := ef.db.Model(&DBcerts).Order("id ASC").Offset(offset).Limit(ef.batchSize).Select(); err != nil {
			fmt.Println(err)
			return err
		}
		var x509List []*CertificateFeatures
		for _, DBcert := range DBcerts {
			bar.Increment()

			cert, err := x509.ParseCertificate(DBcert.Raw)
			if err != nil {
				//log.Debug().Msgf("error parsing the certificate ID = %d", DBcert.ID)
				continue
			}
			x509List = append(x509List, &CertificateFeatures{
				id:   DBcert.ID,
				cert: cert,
			})
		}

		err = ef.getFeatures(x509List)
		if err != nil {
			log.Error().Msg("Error while getting the features")
		}
		err = ef.insert()
		if err != nil {
			log.Error().Msgf("%v", err)
		}
	}
	return nil
}

func (ef *ExtractFeatures) getFeatures(certs []*CertificateFeatures) error {

	for _, c := range certs {

		sf := getSanFeatures(c.cert)

		vl := getValidationLevel(c.cert)

		issuerID, err := ef.getOrCreateIssuer(c.cert.Issuer.String())
		if err != nil {
			return err
		}

		notBefore := &c.cert.NotBefore
		if notBefore.Unix() <= 1 {
			notBefore = nil
		}

		notAfter := &c.cert.NotAfter
		if notAfter.Unix() >= math.MaxInt32 {
			notAfter = nil
		}
		validityPeriod := 0
		if notAfter != nil && notBefore != nil {
			diff := notAfter.Sub(*notBefore)
			validityPeriod = int(diff.Hours())
		}

		uniqueTldsPerDomain := sql.NullFloat64{
			Float64: float64(sf.tlds.UniqueLen()) / float64(len(c.cert.DNSNames)),
			Valid:   len(c.cert.DNSNames) > 0,
		}

		features := Features{
			CertID:              c.id,
			IssuerID:            issuerID,
			Algo:                c.cert.SignatureAlgorithm.String(),
			Country:             strings.Join(c.cert.Subject.Country, ","),
			ValidationLevel:     vl,
			NotBefore:           notBefore,
			NotAfter:            notAfter,
			ValidityPeriod:      validityPeriod,
			DomainCount:         len(c.cert.DNSNames),
			UniqueApexCount:     sf.apexes.UniqueLen(),
			UniqueSldCount:      sf.slds.UniqueLen(),
			ShortestDomain:      sf.sans.Min(),
			LongestDomain:       sf.sans.Max(),
			MeanDomainLength:    sf.sans.Mean(),
			MinSubLabels:        sf.subdomainLabels.Min(),
			MaxSubLabels:        sf.subdomainLabels.Max(),
			MeanSubLabels:       sf.subdomainLabels.Mean(),
			UniqueTlds:          sf.tlds.UniqueLen(),
			UniqueTldsPerDomain: uniqueTldsPerDomain,
			ApexLCS:             sf.lcs.String(),
			LenApexLcs:          sf.lcs.Len(),
			LenApexLcsNorm:      sf.lcs.Normalized(),
		}

		ef.inserts = append(ef.inserts, features)
	}

	return nil
}

func (ef *ExtractFeatures) getOrCreateIssuer(name string) (int, error) {
	issuer, ok := ef.cache.issuers[name]
	if !ok {
		issuer = &Issuer{
			ID:   ef.cache.issuerIDs,
			Name: name,
		}

		if err := ef.db.Insert(issuer); err != nil {
			return 0, errors.Wrap(err, "insert issuer")
		}

		ef.cache.issuers[name] = issuer
		ef.cache.issuerIDs++
	}
	return issuer.ID, nil
}

func (ef *ExtractFeatures) insert() error {
	tx, err := ef.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// inserts
	if len(ef.inserts) > 0 {
		if err := tx.Insert(&ef.inserts); err != nil {
			return errs.Wrap(err, "insert features")
		}
	}

	ef.inserts = NewInserts()

	if err := tx.Commit(); err != nil {
		return errs.Wrap(err, "committing transaction")
	}

	return nil
}
