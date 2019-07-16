package zone

type Zone interface {
	Download() error
	Process(func(domainName string) error) error
}
