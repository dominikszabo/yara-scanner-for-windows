package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("YARA Scanner Server - Network scanner server")
	fmt.Println("Usage: yara-scanner-server [command]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  start                Start the scanner server")
	fmt.Println("  stop                 Stop the scanner server")
	fmt.Println("  help                 Show help")
	fmt.Println("")
	fmt.Println("For more information, visit: https://github.com/dominikszabo/yara-scanner")
	
	if len(os.Args) < 2 {
		os.Exit(0)
	}
}
