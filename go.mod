module github.com/aau-network-security/gollector

go 1.13

require (
	cloud.google.com/go/bigquery v1.8.0 // indirect
	cloud.google.com/go/pubsub v1.5.0 // indirect
	github.com/bippio/go-impala v2.0.0+incompatible
	github.com/cheggaaa/pb v2.0.7+incompatible
	github.com/cheggaaa/pb/v3 v3.0.5
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/go-systemd v0.0.0-20190620071333-e64a0ec8b42a // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/emicklei/proto v1.6.13 // indirect
	github.com/emirpasic/gods v1.12.0 // indirect
	github.com/getsentry/sentry-go v0.3.0
	github.com/gliderlabs/ssh v0.1.4 // indirect
	github.com/go-acme/lego v2.7.2+incompatible
	github.com/go-pg/pg v8.0.6+incompatible
	github.com/gobuffalo/flect v0.1.5 // indirect
	github.com/golang/protobuf v1.4.3
	github.com/golangci/go-tools v0.0.0-20190124090046-35a9f45a5db0 // indirect
	github.com/golangci/gocyclo v0.0.0-20180528144436-0a533e8fa43d // indirect
	github.com/golangci/golangci-lint v1.17.2-0.20190630074125-360a58dca92d // indirect
	github.com/golangci/gosec v0.0.0-20180901114220-8afd9cbb6cfb // indirect
	github.com/golangci/revgrep v0.0.0-20180812185044-276a5c0a1039 // indirect
	github.com/google/certificate-transparency-go v1.1.2-0.20210303154847-1df04e964985
	github.com/google/licenseclassifier v0.0.0-20190501212618-47b603fe1b8c // indirect
	github.com/google/monologue v0.0.0-20190606152607-4b11a32b5934 // indirect
	github.com/google/pprof v0.0.0-20200604032702-163a225fb653 // indirect
	github.com/google/trillian-examples v0.0.0-20190603134952-4e75ba15216c // indirect
	github.com/google/uuid v1.1.2
	github.com/gostaticanalysis/analysisutil v0.0.0-20190329151158-56bca42c7635 // indirect
	github.com/hashicorp/golang-lru v0.5.4
	github.com/ianlancetaylor/demangle v0.0.0-20200524003926-2c5affb30a03 // indirect
	github.com/influxdata/influxdb-client-go/v2 v2.2.0
	github.com/jinzhu/gorm v1.9.11
	github.com/jlaffaye/ftp v0.0.0-20190828173736-6aaa91c7796e
	github.com/letsencrypt/pkcs11key v2.0.1-0.20170608213348-396559074696+incompatible // indirect
	github.com/lib/pq v1.9.0
	github.com/lyft/protoc-gen-validate v0.0.14 // indirect
	github.com/mholt/certmagic v0.7.6-0.20191016061957-c52848a21de3
	github.com/miekg/dns v1.1.22
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/otiai10/copy v1.0.1 // indirect
	github.com/otiai10/curr v0.0.0-20190513014714-f5a3d24e5776 // indirect
	github.com/pelletier/go-toml v1.4.0 // indirect
	github.com/pkg/errors v0.9.1
	github.com/rogpeppe/go-internal v1.3.2 // indirect
	github.com/rs/zerolog v1.15.0
	github.com/shurcooL/go v0.0.0-20190330031554-6713ea532688 // indirect
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/uber/prototool v1.8.1 // indirect
	github.com/vbauerster/mpb/v4 v4.10.1
	github.com/weppos/publicsuffix-go v0.10.0
	github.com/xanzy/ssh-agent v0.2.1 // indirect
	go.etcd.io/etcd v3.3.13+incompatible // indirect
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	golang.org/x/text v0.3.3
	google.golang.org/grpc v1.36.0
	gopkg.in/VividCortex/ewma.v1 v1.1.1 // indirect
	gopkg.in/airbrake/gobrake.v2 v2.0.9 // indirect
	gopkg.in/cheggaaa/pb.v2 v2.0.7 // indirect
	gopkg.in/fatih/color.v1 v1.0.0-00010101000000-000000000000 // indirect
	gopkg.in/gemnasium/logrus-airbrake-hook.v2 v2.1.2 // indirect
	gopkg.in/mattn/go-colorable.v0 v0.0.0-00010101000000-000000000000 // indirect
	gopkg.in/mattn/go-isatty.v0 v0.0.0-00010101000000-000000000000 // indirect
	gopkg.in/src-d/go-billy.v4 v4.3.0 // indirect
	gopkg.in/src-d/go-git-fixtures.v3 v3.5.0 // indirect
	gopkg.in/src-d/go-git.v4 v4.11.0 // indirect
	gopkg.in/yaml.v2 v2.3.0
	mellium.im/sasl v0.2.1 // indirect
	sourcegraph.com/sqs/pbtypes v1.0.0 // indirect
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

replace gopkg.in/mattn/go-colorable.v0 => github.com/mattn/go-colorable v0.1.2

replace gopkg.in/mattn/go-isatty.v0 => github.com/mattn/go-isatty v0.0.7

replace gopkg.in/fatih/color.v1 => github.com/fatih/color v1.10.0
