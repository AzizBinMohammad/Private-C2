package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Private-C2 Builder")
	fmt.Println("Usage: private-c2-builder [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --os        Target OS (windows, linux, darwin)")
	fmt.Println("  --arch      Target architecture (amd64, arm64)")
	fmt.Println("  --mode      Implant mode (session, beacon)")
	fmt.Println("  --transport Transport protocol (mtls, https, dns)")
	fmt.Println("  --output    Output file path")
	fmt.Println("  --format    Output format (exe, dll, shellcode)")

	if len(os.Args) < 2 {
		os.Exit(0)
	}
}
