module github.com/aau-network-security/gollector

go 1.13

require (
	github.com/bippio/go-impala v2.0.0+incompatible
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/getsentry/sentry-go v0.3.0
	github.com/go-acme/lego v2.7.2+incompatible
	github.com/go-pg/pg v8.0.6+incompatible
	github.com/gocql/gocql v0.0.0-20200615160627-420e3b873d91
	github.com/golang/protobuf v1.3.2
	github.com/google/certificate-transparency-go v1.0.22-0.20190613123100-f1b2d813b630
	github.com/google/pprof v0.0.0-20200604032702-163a225fb653 // indirect
	github.com/google/trillian v1.3.2 // indirect
	github.com/google/uuid v1.1.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/ianlancetaylor/demangle v0.0.0-20200524003926-2c5affb30a03 // indirect
	github.com/jinzhu/gorm v1.9.11
	github.com/jlaffaye/ftp v0.0.0-20190828173736-6aaa91c7796e
	github.com/lib/pq v1.2.0
	github.com/mholt/certmagic v0.7.6-0.20191016061957-c52848a21de3
	github.com/miekg/dns v1.1.22
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/pkg/errors v0.8.1
	github.com/rs/zerolog v1.15.0
	github.com/vbauerster/mpb/v4 v4.10.1
	github.com/weppos/publicsuffix-go v0.10.0
	golang.org/x/crypto v0.0.0-20191011191535-87dc89f01550
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20200602225109-6fdc65e7d980 // indirect
	golang.org/x/text v0.3.2
	google.golang.org/grpc v1.24.0
	gopkg.in/yaml.v2 v2.2.4
	mellium.im/sasl v0.2.1 // indirect
)

replace github.com/google/trillian v1.3.2 => github.com/google/trillian v1.3.1

replace github.com/golangci/golangci-lint v1.17.2-0.20190630074125-360a58dca92d => github.com/golangci/golangci-lint v1.21.0

replace google.golang.org/genproto v0.0.0-20170818100345-ee236bd376b0 => google.golang.org/genproto v0.0.0-20191009194640-548a555dbc03

replace github.com/go-critic/go-critic v0.0.0-20181204210945-1df300866540 => github.com/go-critic/go-critic v0.3.5-0.20191013080412-b4b8433b316c

replace github.com/golangci/errcheck v0.0.0-20181003203344-ef45e06d44b6 => github.com/golangci/errcheck v0.0.0-20181223084120-ef45e06d44b6

replace github.com/golangci/go-tools v0.0.0-20180109140146-af6baa5dc196 => github.com/golangci/go-tools v0.0.0-20190124090046-35a9f45a5db0

replace github.com/golangci/gofmt v0.0.0-20181105071733-0b8337e80d98 => github.com/golangci/gofmt v0.0.0-20190930125516-244bba706f1a

replace github.com/golangci/gosec v0.0.0-20180901114220-66fb7fc33547 => github.com/golangci/gosec v0.0.0-20180901114220-8afd9cbb6cfb

replace github.com/golangci/ineffassign v0.0.0-20180808204949-42439a7714cc => github.com/golangci/ineffassign v0.0.0-20180808204949-2ee8f2867dde

replace github.com/golangci/lint-1 v0.0.0-20180610141402-ee948d087217 => github.com/golangci/lint-1 v0.0.0-20181222135242-d2cdd8c08219

replace mvdan.cc/unparam v0.0.0-20190124213536-fbb59629db34 => github.com/mvdan/unparam v0.0.0-20190917161559-b83a221c10a2
