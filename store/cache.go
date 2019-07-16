package store

import (
	"github.com/kdhageman/go-domains/models"
)

type Cache interface {
	GetApex(domain string) (models.Apex, bool)
}

type cache struct {
	apexes map[string]models.Apex
}

func (c *cache) GetApex(domain string) (models.Apex, bool) {
	d, ok := c.apexes[domain]
	return d, ok
}
