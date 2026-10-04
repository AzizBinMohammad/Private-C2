package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Private-C2 Client")
	fmt.Println("Usage: private-c2-client [command]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  sessions    List active sessions")
	fmt.Println("  beacons     List active beacons")
	fmt.Println("  listeners   Manage listeners")
	fmt.Println("  payloads    Generate payloads")
	fmt.Println("  engage      Manage engagements")
	fmt.Println("  audit       Query audit logs")
	fmt.Println()
	fmt.Println("Use --help with any command for details")

	if len(os.Args) < 2 {
		os.Exit(0)
	}
}
