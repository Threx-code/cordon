module example.com/conformance/app

go 1.24

toolchain go1.24.0

require (
	example.com/conformance/localdep v0.0.0
	github.com/google/uuid v1.6.0
	golang.org/x/text v0.21.0
)

require (
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/tools v0.28.0 // indirect
)

replace example.com/conformance/localdep => ./localdep

replace github.com/pkg/errors => github.com/pkg/errors v0.9.1

exclude golang.org/x/text v0.20.0

tool golang.org/x/tools/cmd/stringer
