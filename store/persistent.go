package store

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/aau-network-security/go-domains/ct"
	"github.com/aau-network-security/go-domains/models"
	"github.com/go-pg/pg"
	ct2 "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/jinzhu/gorm"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/publicsuffix"
	"strings"
	"sync"
	"time"
)

var (
	UnsupportedCertTypeErr = errors.New("provided certificate is not supported")
	DefaultOpts            = Opts{
		BatchSize:       20000,
		AllowedInterval: 36 * time.Hour,
	}
)

type EntryExistsErr struct {
	Domain string
}

func (err EntryExistsErr) Error() string {
	return fmt.Sprintf("trying to store zonefile entry for existing domain '%s'", err.Domain)
}

type InvalidDomainErr struct {
	Domain string
}

func (err InvalidDomainErr) Error() string {
	return fmt.Sprintf("cannot store invalid domain: %s", err.Domain)
}

func toApex(fqdn string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(fqdn)
}

func timeFromLogEntry(entry *ct2.LogEntry) time.Time {
	ts := entry.Leaf.TimestampedEntry.Timestamp
	return time.Unix(int64(ts/1000), int64(ts%1000))
}

func certFromLogEntry(entry *ct2.LogEntry) (*x509.Certificate, error) {
	var cert *x509.Certificate
	if entry.Precert != nil {
		cert = entry.Precert.TBSCertificate
	} else if entry.X509Cert != nil {
		cert = entry.X509Cert
	} else {
		return nil, UnsupportedCertTypeErr
	}
	return cert, nil
}

type Config struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	DBName   string `yaml:"dbname"`

	d *gorm.DB
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

type ModelSet struct {
	zoneEntries    map[uint]*models.ZonefileEntry
	apexes         map[uint]*models.Apex
	certs          []*models.Certificate
	logEntries     []*models.LogEntry
	certToFqdns    []*models.CertificateToFqdn
	fqdns          []*models.Fqdn
	passiveEntries []*models.PassiveEntry
}

func (s *ModelSet) Len() int {
	return len(s.zoneEntries) +
		len(s.apexes) +
		len(s.certs) +
		len(s.logEntries) +
		len(s.certToFqdns) +
		len(s.fqdns) +
		len(s.passiveEntries)
}

func (ms *ModelSet) zoneEntryList() []*models.ZonefileEntry {
	var res []*models.ZonefileEntry
	for _, v := range ms.zoneEntries {
		res = append(res, v)
	}
	return res
}

func (ms *ModelSet) apexList() []*models.Apex {
	var res []*models.Apex
	for _, v := range ms.apexes {
		res = append(res, v)
	}
	return res
}

func NewModelSet() ModelSet {
	return ModelSet{
		zoneEntries:    make(map[uint]*models.ZonefileEntry),
		apexes:         make(map[uint]*models.Apex),
		fqdns:          []*models.Fqdn{},
		certToFqdns:    []*models.CertificateToFqdn{},
		certs:          []*models.Certificate{},
		logEntries:     []*models.LogEntry{},
		passiveEntries: []*models.PassiveEntry{},
	}
}

type postHook func(*Store) error

type Ids struct {
	zoneEntries, apexes, tlds, certs, logs, fqdns, recordTypes, measurements, stages uint
}

type splunkEntryMap struct {
	byQueryType map[string]map[string]*models.PassiveEntry
}

func (m *splunkEntryMap) get(query, queryType string) (*models.PassiveEntry, bool) {
	byQType, ok := m.byQueryType[queryType]
	if !ok {
		return nil, false
	}
	res, ok := byQType[query]
	return res, ok
}

func (m *splunkEntryMap) add(query, queryType string, entry *models.PassiveEntry) {
	byQType, ok := m.byQueryType[queryType]
	if !ok {
		byQType = make(map[string]*models.PassiveEntry)
	}
	byQType[query] = entry
	m.byQueryType[queryType] = byQType
}

func (m *splunkEntryMap) len() int {
	sum := 0
	for _, v := range m.byQueryType {
		sum += len(v)
	}
	return sum
}

func newSplunkEntryMap() splunkEntryMap {
	return splunkEntryMap{
		byQueryType: make(map[string]map[string]*models.PassiveEntry),
	}
}

type Store struct {
	conf                  Config
	db                    *pg.DB
	apexByName            map[string]*models.Apex
	apexById              map[uint]*models.Apex
	zoneEntriesByApexName map[string]*models.ZonefileEntry
	tldByName             map[string]*models.Tld
	certByFingerprint     map[string]*models.Certificate
	logByUrl              map[string]*models.Log
	fqdnByName            map[string]*models.Fqdn
	recordTypeByName      map[string]*models.RecordType
	passiveEntryByFqdn    splunkEntryMap
	m                     *sync.Mutex
	ids                   Ids
	allowedInterval       time.Duration
	batchSize             int
	postHooks             []postHook
	inserts               ModelSet
	updates               ModelSet
	curStage              *models.Stage
	curMeasurement        *models.Measurement
}

func (s *Store) RunPostHooks() error {
	s.m.Lock()
	defer s.m.Unlock()
	return s.runPostHooks()
}

func (s *Store) runPostHooks() error {
	for _, h := range s.postHooks {
		if err := h(s); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) conditionalPostHooks() error {
	if s.updates.Len()+s.inserts.Len() >= s.batchSize {
		return s.runPostHooks()
	}
	return nil
}

func (s *Store) getOrCreateTld(tld string) (*models.Tld, error) {
	t, ok := s.tldByName[tld]
	if !ok {
		t = &models.Tld{
			ID:  s.ids.tlds,
			Tld: tld,
		}
		if err := s.db.Insert(t); err != nil {
			return nil, err
		}

		s.tldByName[tld] = t
		s.ids.tlds++
	}
	return t, nil
}

func (s *Store) storeApexDomain(name string) (*models.Apex, error) {
	splitted := strings.Split(name, ".")
	if len(splitted) == 1 {
		return nil, InvalidDomainErr{name}
	}

	tld, err := s.getOrCreateTld(splitted[len(splitted)-1])
	if err != nil {
		return nil, err
	}

	model := &models.Apex{
		ID:    s.ids.apexes,
		Apex:  name,
		TldID: tld.ID,
	}

	s.apexByName[name] = model
	s.inserts.apexes[model.ID] = model
	s.ids.apexes++

	if err := s.conditionalPostHooks(); err != nil {
		return nil, err
	}

	return model, nil
}

func (s *Store) getOrCreateApex(domain string) (*models.Apex, error) {
	res, ok := s.apexByName[domain]
	if !ok {
		splitted := strings.Split(domain, ".")
		if len(splitted) == 1 {
			return nil, InvalidDomainErr{domain}
		}

		tld, err := s.getOrCreateTld(splitted[len(splitted)-1])
		if err != nil {
			return nil, err
		}

		model := &models.Apex{
			ID:    s.ids.apexes,
			Apex:  domain,
			TldID: tld.ID,
		}

		s.apexByName[domain] = model
		s.inserts.apexes[model.ID] = model
		s.ids.apexes++

		res = model
	}
	return res, nil
}

func (s *Store) StoreZoneEntry(t time.Time, domain string) (*models.ZonefileEntry, error) {
	s.m.Lock()
	defer s.m.Unlock()

	apex, err := toApex(domain)
	if err != nil {
		return nil, err
	}

	apexModel, err := s.getOrCreateApex(apex)
	if err != nil {
		return nil, err
	}

	existingZoneEntry, ok := s.zoneEntriesByApexName[apex]
	if !ok {
		// non-active domain, create a new zone entry
		newZoneEntry := &models.ZonefileEntry{
			ID:        s.ids.zoneEntries,
			ApexID:    apexModel.ID,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
			StageID:   s.curStage.ID,
		}

		s.zoneEntriesByApexName[apex] = newZoneEntry
		s.inserts.zoneEntries[newZoneEntry.ID] = newZoneEntry
		s.ids.zoneEntries++

		if err := s.conditionalPostHooks(); err != nil {
			return nil, err
		}

		return newZoneEntry, nil
	}

	// active domain
	if existingZoneEntry.LastSeen.Before(time.Now().Add(-s.allowedInterval)) {
		// detected re-registration, set old entry inactive and create new

		existingZoneEntry.Active = false
		s.updates.zoneEntries[existingZoneEntry.ID] = existingZoneEntry

		newZoneEntry := &models.ZonefileEntry{
			ID:        s.ids.zoneEntries,
			ApexID:    apexModel.ID,
			FirstSeen: t,
			LastSeen:  t,
			Active:    true,
			StageID:   s.curStage.ID,
		}

		s.zoneEntriesByApexName[apex] = newZoneEntry
		s.inserts.zoneEntries[newZoneEntry.ID] = newZoneEntry
		s.ids.zoneEntries++

		if err := s.conditionalPostHooks(); err != nil {
			return nil, err
		}

		return newZoneEntry, nil
	}

	// update existing
	existingZoneEntry.LastSeen = t
	s.updates.zoneEntries[existingZoneEntry.ID] = existingZoneEntry

	if err := s.conditionalPostHooks(); err != nil {
		return nil, err
	}

	return existingZoneEntry, nil
}

func (s *Store) getOrCreateLog(log ct.Log) (*models.Log, error) {
	l, ok := s.logByUrl[log.Url]
	if !ok {
		l = &models.Log{
			ID:          s.ids.logs,
			Url:         log.Url,
			Description: log.Description,
		}
		if err := s.db.Insert(l); err != nil {
			return nil, err
		}

		s.logByUrl[log.Url] = l
		s.ids.logs++
	}
	return l, nil
}

func (s *Store) getOrCreateFqdn(domain string) (*models.Fqdn, error) {
	f, ok := s.fqdnByName[domain]
	if !ok {
		apex, err := toApex(domain)
		if err != nil {
			return nil, err
		}

		a, err := s.getOrCreateApex(apex)
		if err != nil {
			return nil, err
		}

		f = &models.Fqdn{
			ID:     s.ids.fqdns,
			Fqdn:   domain,
			ApexID: a.ID,
		}
		s.inserts.fqdns = append(s.inserts.fqdns, f)
		s.fqdnByName[domain] = f
		s.ids.fqdns++
	}
	return f, nil
}

func (s *Store) getOrCreateCertificate(entry *ct2.LogEntry) (*models.Certificate, error) {
	c, err := certFromLogEntry(entry)
	if err != nil {
		return nil, err
	}

	fp := fmt.Sprintf("%x", sha256.Sum256(c.Raw))

	cert, ok := s.certByFingerprint[fp]
	if !ok {
		cert = &models.Certificate{
			ID:                s.ids.certs,
			Sha256Fingerprint: fp,
		}

		// create an association between FQDNs in database and the newly created certificate
		for _, d := range c.DNSNames {
			fqdn, err := s.getOrCreateFqdn(d)
			if err != nil {
				return nil, err
			}
			ctof := models.CertificateToFqdn{
				CertificateID: cert.ID,
				FqdnID:        fqdn.ID,
			}
			s.inserts.certToFqdns = append(s.inserts.certToFqdns, &ctof)
		}

		s.inserts.certs = append(s.inserts.certs, cert)
		s.certByFingerprint[fp] = cert
		s.ids.certs++
	}
	return cert, nil
}

func (s *Store) StoreLogEntry(entry *ct2.LogEntry, log ct.Log) error {
	s.m.Lock()
	defer s.m.Unlock()

	l, err := s.getOrCreateLog(log)
	if err != nil {
		return err
	}

	cert, err := s.getOrCreateCertificate(entry)
	if err != nil {
		return err
	}

	ts := timeFromLogEntry(entry)

	le := models.LogEntry{
		LogID:         l.ID,
		Index:         uint(entry.Index),
		CertificateID: cert.ID,
		Timestamp:     ts,
		StageID:       s.curStage.ID,
	}

	s.inserts.logEntries = append(s.inserts.logEntries, &le)

	return s.conditionalPostHooks()
}

func (s *Store) getorCreateRecordType(rtype string) (*models.RecordType, error) {
	rt, ok := s.recordTypeByName[rtype]
	if !ok {
		rt = &models.RecordType{
			ID:   s.ids.recordTypes,
			Type: rtype,
		}
		if err := s.db.Insert(rt); err != nil {
			return nil, err
		}

		s.recordTypeByName[rtype] = rt
		s.ids.recordTypes++
	}
	return rt, nil
}

func (s *Store) StorePassiveEntry(query string, queryType string, t time.Time) (*models.PassiveEntry, error) {
	s.m.Lock()
	defer s.m.Unlock()

	query = strings.ToLower(query)
	queryType = strings.ToLower(queryType)

	pe, ok := s.passiveEntryByFqdn.get(query, queryType)
	if !ok {
		// create a new entry
		fqdn, err := s.getOrCreateFqdn(query)
		if err != nil {
			return nil, err
		}

		rt, err := s.getorCreateRecordType(queryType)
		if err != nil {
			return nil, err
		}

		pe = &models.PassiveEntry{
			FqdnID:       fqdn.ID,
			FirstSeen:    t,
			RecordTypeID: rt.ID,
			StageID:      s.curStage.ID,
		}

		s.passiveEntryByFqdn.add(query, queryType, pe)
		s.inserts.passiveEntries = append(s.inserts.passiveEntries, pe)
	} else if t.Before(pe.FirstSeen) {
		// see if we must update the existing one
		pe.FirstSeen = t
		s.updates.passiveEntries = append(s.updates.passiveEntries, pe)
	}

	return pe, nil
}

// use Gorm's auto migrate functionality
func (s *Store) migrate() error {
	g, err := s.conf.Open()
	if err != nil {
		return err
	}

	migrateExamples := []interface{}{
		&models.Apex{},
		&models.ZonefileEntry{},
		&models.Tld{},
		&models.Fqdn{},
		&models.CertificateToFqdn{},
		&models.Certificate{},
		&models.LogEntry{},
		&models.Log{},
		&models.RecordType{},
		&models.PassiveEntry{},
		&models.Measurement{},
		&models.Stage{},
	}
	for _, ex := range migrateExamples {
		if err := g.AutoMigrate(ex).Error; err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) init() error {
	var apexes []*models.Apex
	if err := s.db.Model(&apexes).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, apex := range apexes {
		s.apexByName[apex.Apex] = apex
		s.apexById[apex.ID] = apex
	}

	var entries []*models.ZonefileEntry
	if err := s.db.Model(&entries).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, entry := range entries {
		apex := s.apexById[entry.ApexID]
		s.zoneEntriesByApexName[apex.Apex] = entry
	}

	var tlds []*models.Tld
	if err := s.db.Model(&tlds).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, tld := range tlds {
		s.tldByName[tld.Tld] = tld
	}

	var fqdns []*models.Fqdn
	if err := s.db.Model(&fqdns).Order("id ASC").Select(); err != nil {
		return err
	}
	fqdnsById := make(map[uint]*models.Fqdn)
	for _, fqdn := range fqdns {
		s.fqdnByName[fqdn.Fqdn] = fqdn
		fqdnsById[fqdn.ID] = fqdn
	}

	var logs []*models.Log
	if err := s.db.Model(&logs).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, l := range logs {
		s.logByUrl[l.Url] = l
	}

	var certs []*models.Certificate
	if err := s.db.Model(&certs).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, c := range certs {
		s.certByFingerprint[c.Sha256Fingerprint] = c
	}

	var rtypes []*models.RecordType
	if err := s.db.Model(&rtypes).Order("id ASC").Select(); err != nil {
		return err
	}
	rtypeById := make(map[uint]*models.RecordType)
	for _, rtype := range rtypes {
		s.recordTypeByName[rtype.Type] = rtype
		rtypeById[rtype.ID] = rtype
	}

	var passiveEntries []*models.PassiveEntry
	if err := s.db.Model(&passiveEntries).Order("id ASC").Select(); err != nil {
		return err
	}
	for _, entry := range passiveEntries {
		fqdn := fqdnsById[entry.FqdnID]
		rtype := rtypeById[entry.RecordTypeID]
		s.passiveEntryByFqdn.add(fqdn.Fqdn, rtype.Type, entry)
	}

	var measurements []*models.Measurement
	if err := s.db.Model(&measurements).Order("id ASC").Select(); err != nil {
		return err
	}

	var stages []*models.Stage
	if err := s.db.Model(&stages).Order("id ASC").Select(); err != nil {
		return err
	}

	s.ids.apexes = 1
	if len(apexes) > 0 {
		s.ids.apexes = apexes[len(apexes)-1].ID + 1
	}
	s.ids.zoneEntries = 1
	if len(entries) > 0 {
		s.ids.zoneEntries = entries[len(entries)-1].ID + 1
	}
	s.ids.tlds = 1
	if len(tlds) > 0 {
		s.ids.tlds = tlds[len(tlds)-1].ID + 1
	}
	s.ids.fqdns = 1
	if len(fqdns) > 0 {
		s.ids.fqdns = fqdns[len(fqdns)-1].ID + 1
	}
	s.ids.logs = 1
	if len(logs) > 0 {
		s.ids.logs = logs[len(logs)-1].ID + 1
	}
	s.ids.certs = 1
	if len(certs) > 0 {
		s.ids.certs = certs[len(certs)-1].ID + 1
	}
	s.ids.recordTypes = 1
	if len(rtypes) > 0 {
		s.ids.recordTypes = rtypes[len(rtypes)-1].ID + 1
	}
	s.ids.measurements = 1
	if len(measurements) > 0 {
		s.ids.measurements = measurements[len(measurements)-1].ID + 1
	}
	s.ids.stages = 1
	if len(stages) > 0 {
		s.ids.stages = stages[len(stages)-1].ID + 1
	}

	return nil
}

type Opts struct {
	BatchSize       int
	AllowedInterval time.Duration
}

func NewStore(conf Config, opts Opts) (*Store, error) {
	pgOpts := pg.Options{
		User:     conf.User,
		Password: conf.Password,
		Addr:     fmt.Sprintf("%s:%d", conf.Host, conf.Port),
		Database: conf.DBName,
	}

	db := pg.Connect(&pgOpts)

	s := Store{
		conf:                  conf,
		db:                    db,
		apexByName:            make(map[string]*models.Apex),
		apexById:              make(map[uint]*models.Apex),
		zoneEntriesByApexName: make(map[string]*models.ZonefileEntry),
		tldByName:             make(map[string]*models.Tld),
		fqdnByName:            make(map[string]*models.Fqdn),
		logByUrl:              make(map[string]*models.Log),
		certByFingerprint:     make(map[string]*models.Certificate),
		passiveEntryByFqdn:    newSplunkEntryMap(),
		recordTypeByName:      make(map[string]*models.RecordType),
		allowedInterval:       opts.AllowedInterval,
		batchSize:             opts.BatchSize,
		m:                     &sync.Mutex{},
		postHooks:             []postHook{},
		inserts:               NewModelSet(),
		updates:               NewModelSet(),
		ids:                   Ids{},
	}

	postHook := func(s *Store) error {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()

		// inserts
		if len(s.inserts.apexes) > 0 {
			a := s.inserts.apexList()
			if err := tx.Insert(&a); err != nil {
				return err
			}
		}
		if len(s.inserts.zoneEntries) > 0 {
			z := s.inserts.zoneEntryList()
			if err := tx.Insert(&z); err != nil {
				return err
			}
		}
		if len(s.inserts.logEntries) > 0 {
			if err := tx.Insert(&s.inserts.logEntries); err != nil {
				return err
			}
		}
		if len(s.inserts.certs) > 0 {
			if err := tx.Insert(&s.inserts.certs); err != nil {
				return err
			}
		}
		if len(s.inserts.certToFqdns) > 0 {
			if err := tx.Insert(&s.inserts.certToFqdns); err != nil {
				return err
			}
		}
		if len(s.inserts.fqdns) > 0 {
			if err := tx.Insert(&s.inserts.fqdns); err != nil {
				return err
			}
		}
		if len(s.inserts.passiveEntries) > 0 {
			if err := tx.Insert(&s.inserts.passiveEntries); err != nil {
				return err
			}
		}

		// updates
		if len(s.updates.apexes) > 0 {
			a := s.updates.apexList()
			if err := tx.Update(&a); err != nil {
				return err
			}
		}
		if len(s.updates.zoneEntries) > 0 {
			z := s.updates.zoneEntryList()
			_, err := tx.Model(&z).Column("last_seen").Update()
			if err != nil {
				return err
			}
		}
		if len(s.updates.passiveEntries) > 0 {
			if _, err := tx.Model(&s.updates.passiveEntries).Column("first_seen").Update(); err != nil {
				return err
			}
		}

		s.updates = NewModelSet()
		s.inserts = NewModelSet()

		return tx.Commit()
	}

	s.postHooks = append(s.postHooks, postHook)

	if err := s.migrate(); err != nil {
		return nil, err
	}

	if err := s.init(); err != nil {
		return nil, err
	}
	return &s, nil
}
