package zone

type DomainFunc func(string) error

type Zone interface {
	Process(DomainFunc) error
}
