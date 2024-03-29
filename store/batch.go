package store

import (
	"github.com/aau-network-security/gollector/store/models"
	"github.com/pkg/errors"
)

type domainstruct struct {
	obj    interface{}
	create bool
	domain *domain
}

type certstruct struct {
	cert  *models.Certificate
	entry LogEntry
	sid   uint
}

var cacheNotFound = errors.New("not found in the cache")

type zoneentrystruct struct {
	ze   *models.ZonefileEntry
	apex string
}

type passiveentrystruct struct {
	pe   *models.PassiveEntry
	fqdn string
}

type entradaentrystruct struct {
	ee   *models.EntradaEntry
	fqdn string
}

type BatchEntities struct {
	size                   int
	tldByName              map[string]*domainstruct
	tldAnonByName          map[string]*domainstruct
	publicSuffixByName     map[string]*domainstruct
	publicSuffixAnonByName map[string]*domainstruct
	apexByName             map[string]*domainstruct
	apexByNameAnon         map[string]*domainstruct
	fqdnByName             map[string]*domainstruct
	fqdnByNameAnon         map[string]*domainstruct
	certByFingerprint      map[string]*certstruct
	zoneEntries            []*zoneentrystruct
	passiveEntries         []*passiveentrystruct
	entradaEntries         []*entradaentrystruct
}

func (be *BatchEntities) AddFqdn(domain *domain, anon bool) {
	existingFqdn, ok := be.fqdnByName[domain.fqdn.normal]
	if ok {
		existingFqdn.create = existingFqdn.create || !anon
		be.fqdnByName[domain.fqdn.normal] = existingFqdn
	} else {
		be.fqdnByName[domain.fqdn.normal] = &domainstruct{
			domain: domain,
			create: !anon,
		}
	}

	existingFqdnAnon, ok := be.fqdnByNameAnon[domain.fqdn.anon]
	if ok {
		existingFqdnAnon.create = existingFqdnAnon.create || anon
		be.fqdnByNameAnon[domain.fqdn.anon] = existingFqdnAnon
	} else {
		be.fqdnByNameAnon[domain.fqdn.anon] = &domainstruct{
			domain: domain,
			create: anon,
		}
	}

	be.AddApex(domain, anon)
}

func (be *BatchEntities) AddApex(domain *domain, anon bool) {
	existingApex, ok := be.apexByName[domain.apex.normal]
	if ok {
		existingApex.create = existingApex.create || !anon
		be.apexByName[domain.apex.normal] = existingApex
	} else {
		be.apexByName[domain.apex.normal] = &domainstruct{
			domain: domain,
			create: !anon,
		}
	}

	existingApexAnon, ok := be.apexByNameAnon[domain.apex.anon]
	if ok {
		existingApexAnon.create = existingApexAnon.create || anon
		be.apexByNameAnon[domain.apex.anon] = existingApexAnon
	} else {
		be.apexByNameAnon[domain.apex.anon] = &domainstruct{
			domain: domain,
			create: anon,
		}
	}

	be.AddPublicSuffix(domain, anon)

}

func (be *BatchEntities) AddPublicSuffix(domain *domain, anon bool) {
	existingPublicSuffix, ok := be.publicSuffixByName[domain.publicSuffix.normal]
	if ok {
		existingPublicSuffix.create = existingPublicSuffix.create || !anon
		be.publicSuffixByName[domain.publicSuffix.normal] = existingPublicSuffix
	} else {
		be.publicSuffixByName[domain.publicSuffix.normal] = &domainstruct{
			domain: domain,
			create: !anon,
		}
	}

	existingPublicSuffixAnon, ok := be.publicSuffixAnonByName[domain.publicSuffix.anon]
	if ok {
		existingPublicSuffixAnon.create = existingPublicSuffixAnon.create || anon
		be.publicSuffixAnonByName[domain.publicSuffix.anon] = existingPublicSuffixAnon
	} else {
		be.publicSuffixAnonByName[domain.publicSuffix.anon] = &domainstruct{
			domain: domain,
			create: anon,
		}
	}

	be.AddTld(domain, anon)
}

func (be *BatchEntities) AddTld(domain *domain, anon bool) {
	existingTld, ok := be.tldByName[domain.tld.normal]
	if ok {
		// creation has precedence over not creating
		existingTld.create = existingTld.create || !anon
		be.tldByName[domain.tld.normal] = existingTld
	} else {
		be.tldByName[domain.tld.normal] = &domainstruct{
			domain: domain,
			create: !anon,
		}
	}

	existingTldAnon, ok := be.tldAnonByName[domain.tld.anon]
	if ok {
		existingTldAnon.create = existingTldAnon.create || anon
		be.tldAnonByName[domain.tld.anon] = existingTldAnon
	} else {
		be.tldAnonByName[domain.tld.anon] = &domainstruct{
			domain: domain,
			create: anon,
		}
	}
}

// used to determine if the batch is full, which depends on the number of zone entries or the number of log entries (measured by certs)
func (be *BatchEntities) IsFull() bool {
	return be.Len() >= be.size
}

func (be *BatchEntities) Len() int {
	return len(be.zoneEntries) + len(be.certByFingerprint) + len(be.passiveEntries) + len(be.entradaEntries)
}

func (be *BatchEntities) Reset() {
	be.tldByName = make(map[string]*domainstruct)
	be.tldAnonByName = make(map[string]*domainstruct)
	be.publicSuffixByName = make(map[string]*domainstruct)
	be.publicSuffixAnonByName = make(map[string]*domainstruct)
	be.apexByName = make(map[string]*domainstruct)
	be.apexByNameAnon = make(map[string]*domainstruct)
	be.fqdnByName = make(map[string]*domainstruct)
	be.fqdnByNameAnon = make(map[string]*domainstruct)
	be.certByFingerprint = make(map[string]*certstruct)
	be.zoneEntries = []*zoneentrystruct{}
	be.passiveEntries = []*passiveentrystruct{}
	be.entradaEntries = []*entradaentrystruct{}
}

func NewBatchEntities(size int) BatchEntities {
	res := BatchEntities{
		size: size,
	}
	res.Reset()
	return res
}
