package main

import (
	"fmt"
	"os"
	"github.com/yourusername/secureconfig"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: secureconfig-cli <key> <value>")
		fmt.Println("Example: secureconfig-cli database.password mySecretPassword")
		os.Exit(1)
	}

	key := os.Args[1]
	value := os.Args[2]

	config, err := secureconfig.NewConfig()
	if err != nil {
		fmt.Printf("Error initializing config: %v\n", err)
		os.Exit(1)
	}

	if err := config.Store(key, value); err != nil {
		fmt.Printf("Error storing value: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully stored encrypted value for key: %s\n", key)
}
