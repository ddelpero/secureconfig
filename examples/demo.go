package main

import (
	"fmt"
	"log"
	"os"

	"github.com/ddelpero/secureconfig"
)

func main() {
	// Clean up any existing test file
	os.Remove("test_secureconfig.bin")

	fmt.Println("=== SecureConfig Demo ===")

	// Create a new configuration
	config, err := secureconfig.NewConfigWithFile("test_secureconfig.bin")
	if err != nil {
		log.Fatal("Failed to create config:", err)
	}

	fmt.Println("✓ Created new secure configuration")

	// Store some test values
	testData := map[string]string{
		"database.password":   "superSecret123!",
		"api.stripe.key":      "sk_live_1234567890",
		"jwt.secret":          "my-jwt-secret-key",
		"email.smtp.password": "smtp-password-456",
	}

	for key, value := range testData {
		err := config.Store(key, value)
		if err != nil {
			log.Fatal("Failed to store", key, ":", err)
		}
		fmt.Printf("✓ Stored: %s\n", key)
	}

	fmt.Println("\n=== Retrieving Values ===")

	// Retrieve and verify values
	for key, expectedValue := range testData {
		retrievedValue, err := config.Retrieve(key)
		if err != nil {
			log.Fatal("Failed to retrieve", key, ":", err)
		}

		if retrievedValue == expectedValue {
			fmt.Printf("✓ %s: %s\n", key, retrievedValue)
		} else {
			fmt.Printf("✗ %s: expected '%s', got '%s'\n", key, expectedValue, retrievedValue)
		}
	}

	// List all keys
	fmt.Println("\n=== Available Keys ===")
	keys, err := config.ListKeys()
	if err != nil {
		log.Fatal("Failed to list keys:", err)
	}

	for _, key := range keys {
		fmt.Printf("  - %s\n", key)
	}

	// Test deletion
	fmt.Println("\n=== Testing Deletion ===")
	err = config.Delete("jwt.secret")
	if err != nil {
		log.Fatal("Failed to delete key:", err)
	}
	fmt.Println("✓ Deleted jwt.secret")

	// Try to retrieve deleted key
	_, err = config.Retrieve("jwt.secret")
	if err != nil {
		fmt.Println("✓ Confirmed deletion:", err)
	}

	fmt.Println("\n=== Demo Complete ===")
	fmt.Println("Check the generated test_secureconfig.bin file!")
	fmt.Println("The binary format provides enhanced security by obfuscating the data structure.")
}
