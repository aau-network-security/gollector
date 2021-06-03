package store

import (
	"errors"
	"github.com/aau-network-security/gollector/store/models"
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

// used to determine if the batch is full, which depends on the number of zone entries or the number of log entries (measured by certs)
func (be *BatchEntities) IsFull() bool {
	return be.Len() >= be.size
}

func (be *BatchEntities) Len() int {
	return len(be.zoneEntries) + len(be.certByFingerprint) + len(be.passiveEntries)
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
}

func NewBatchEntities(size int) BatchEntities {
	res := BatchEntities{
		size: size,
	}
	res.Reset()
	return res
}
