package extract_features

import (
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"math"
	"strings"
	"sync"

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
	}

	g, err := conf.Open()
	if err != nil {
		return nil, err
	}

	if err := g.AutoMigrate(Features{}).Error; err != nil {
		return nil, err
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

	for offset := 0; offset < count; offset += ef.batchSize {

		var DBcerts []*models.Certificate
		if err := ef.db.Model(&DBcerts).Order("id ASC").Offset(offset).Limit(ef.batchSize).Select(); err != nil {
			return err
		}
		var x509List []*CertificateFeatures
		for _, DBcert := range DBcerts {
			cert, err := x509.ParseCertificate(DBcert.Raw)
			if err != nil {
				log.Debug().Msgf("error parsing the"+
					" certificate ID = %d", DBcert.ID)
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
	//todo Get the certificate from bulldozer and call getFeatures function

	return nil
}

func (ef *ExtractFeatures) getFeatures(certs []*CertificateFeatures) error {

	for _, c := range certs {

		fmt.Println(c.cert.DNSNames)
		sf := getSanFeatures(c.cert)

		vl := getValidationLevel(c.cert)

		//issuerID, err := getOrCreateIssuer(c.cert.Issuer.CommonName)
		//if err != nil {
		//	return err
		//}

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
			diff := notBefore.Sub(*notAfter)
			validityPeriod = int(diff.Hours())
		}

		uniqueTldsPerDomain := sql.NullFloat64{
			Float64: float64(sf.tlds.UniqueLen()) / float64(len(c.cert.DNSNames)),
			Valid:   len(c.cert.DNSNames) > 0,
		}

		features := Features{
			CertID:              c.id,
			IssuerID:            c.id,
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

func getOrCreateIssuer(name string) (uint, error) {
	//todo create this function
	return 0, nil
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
