module github.com/azizbinmohammad/private-c2/cmd/implant

go 1.23

require github.com/azizbinmohammad/private-c2/pkg v0.0.0

require (
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
)

replace github.com/azizbinmohammad/private-c2/pkg => ../../pkg
