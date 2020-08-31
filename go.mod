module github.com/owncloud/ocis-phoenix

go 1.13

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.1
	contrib.go.opencensus.io/exporter/ocagent v0.6.0
	contrib.go.opencensus.io/exporter/zipkin v0.1.1
	github.com/UnnoTed/fileb0x v1.1.4
	github.com/go-chi/chi v4.1.2+incompatible
	github.com/go-playground/universal-translator v0.17.0 // indirect
	github.com/mholt/certmagic v0.9.1 // indirect
	github.com/micro/cli/v2 v2.1.2
	github.com/micro/go-micro v1.18.0 // indirect
	github.com/oklog/run v1.1.0
	github.com/openzipkin/zipkin-go v0.2.2
	github.com/owncloud/ocis-accounts v0.4.2-0.20200828150703-2ca83cf4ac20 // indirect
	github.com/owncloud/ocis-pkg v1.3.0 // indirect
	github.com/owncloud/ocis-pkg/v2 v2.4.1-0.20200828095914-d3b859484b2b
	github.com/restic/calens v0.2.0
	github.com/spf13/viper v1.7.0
	go.opencensus.io v0.22.4
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
	google.golang.org/grpc/examples v0.0.0-20200824180931-410880dd7d91 // indirect
	gopkg.in/go-playground/validator.v9 v9.31.0 // indirect
)

replace google.golang.org/grpc => google.golang.org/grpc v1.26.0
