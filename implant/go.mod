module github.com/azizbinmohammad/private-c2/implant

go 1.23

replace github.com/azizbinmohammad/private-c2/pkg => ../pkg

require (
	github.com/azizbinmohammad/private-c2/pkg v0.0.0-00010101000000-000000000000
	golang.org/x/sys v0.26.0
)

require golang.org/x/crypto v0.28.0 // indirect
