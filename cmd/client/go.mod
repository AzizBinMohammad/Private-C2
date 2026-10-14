module github.com/azizbinmohammad/private-c2/cmd/client

go 1.23

require github.com/azizbinmohammad/private-c2/client v0.0.0

replace (
	github.com/azizbinmohammad/private-c2/client => ../../client
	github.com/azizbinmohammad/private-c2/pkg => ../../pkg
)
