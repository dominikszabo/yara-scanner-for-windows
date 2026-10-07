package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("YARA Scanner Agent - Windows endpoint scanner")
	fmt.Println("Usage: yara-scanner-agent [command]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  scan <path>          Scan a file or directory")
	fmt.Println("  scan-processes       Scan running processes")
	fmt.Println("  scan-memory          Scan process memory")
	fmt.Println("  list-rules           List loaded YARA rules")
	fmt.Println("  help                 Show help")
	fmt.Println("")
	fmt.Println("For more information, visit: https://github.com/dominikszabo/yara-scanner")
	
	if len(os.Args) < 2 {
		os.Exit(0)
	}
}
