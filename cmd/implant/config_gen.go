package main

// embeddedConfigJSON is replaced by the payload builder using go build's
// -overlay flag. The empty default keeps a normal `go build ./cmd/implant`
// working for development.
const embeddedConfigJSON = ""
