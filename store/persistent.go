package store

type Store interface {
	StoreDomain(domain string)
}

type store struct {
	cache Cache
}

func (s *store) StoreDomain(domain string) {
	// todo: implement
}

func NewStore(cache Cache) Store {
	s := store{
		cache: cache,
	}
	return &s
}
