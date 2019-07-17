package store

import (
	"github.com/kdhageman/go-domains/models"
)

type Cache interface {
	Restore() error
	GetApex(domain string) (models.Apex, bool)
}

type cache struct {
	apexes map[string]models.Apex
}

func (c *cache) Restore() error {
	// todo: restore cache from the current state of the database
	return nil
}

func (c *cache) GetApex(domain string) (models.Apex, bool) {
	d, ok := c.apexes[domain]
	return d, ok
}

func NewCache() Cache {
	c := cache{
		apexes: make(map[string]models.Apex),
	}
	return &c
}
