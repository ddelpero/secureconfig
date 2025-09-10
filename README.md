# SecureConfig

A secure, encrypted configuration management package for Go applications. Store sensitive configuration data like API keys, database passwords, and other secrets with AES-256-GCM encryption.

## Features

- **AES-256-GCM Encryption**: Industry-standard encryption for maximum security
- **Simple API**: Easy-to-use interface for storing and retrieving encrypted values
- **Auto Key Generation**: Automatically generates and manages encryption keys
- **Binary Storage**: Stores encrypted data in secure binary format (not human-readable)
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **No External Dependencies**: Uses only Go standard library

## Installation

```bash
# Install the package
go get github.com/ddelpero/secureconfig

# Or install the latest version
go get github.com/ddelpero/secureconfig@latest
```

## Quick Start

### Basic Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/ddelpero/secureconfig/secureconfig"
)

func main() {
    // Create a new secure configuration
    config, err := secureconfig.NewConfig()
    if err != nil {
        log.Fatal(err)
    }

    // Store an encrypted value
    err = config.Store("database.password", "mySecretPassword123")
    if err != nil {
        log.Fatal(err)
    }

    // Retrieve the decrypted value
    password, err := config.Retrieve("database.password")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Password:", password) // Output: mySecretPassword123
}
```

### Using Custom Config File

```go
// Use a custom configuration file
config, err := secureconfig.NewConfigWithFile("myapp.secrets.bin")
if err != nil {
    log.Fatal(err)
}
```

## CLI Tool

A command-line tool is included for managing secrets from the terminal:

```bash
# Install the CLI tool
go install github.com/ddelpero/secureconfig/cmd@main

# Store a secret
secureconfig-cli database.password mySecretPassword123

# The encrypted data is stored in secureconfig.bin
```

### Building CLI Tool Locally

If you prefer to build the CLI tool locally:

```bash
# Clone the repository
git clone https://github.com/ddelpero/secureconfig.git
cd secureconfig

# Build the CLI tool
go build -o secureconfig-cli cmd/main.go

# Use the tool
./secureconfig-cli database.password mySecretPassword123
```

**Note**: The CLI tool is located in `cmd/main.go` and provides a simple interface for storing encrypted values. For more advanced operations (retrieve, list, delete), use the Go API directly in your applications.

## API Reference

### Types

#### Config
The main configuration struct that handles encryption and storage.

### Functions

#### NewConfig() (*Config, error)
Creates a new secure configuration instance using the default file (`secureconfig.bin`).

#### NewConfigWithFile(filename string) (*Config, error)
Creates a new secure configuration instance with a custom filename.

### Methods

#### (c *Config) Store(key, value string) error
Encrypts and stores a key-value pair.

#### (c *Config) Retrieve(key string) (string, error)
Retrieves and decrypts a value by key. Returns an error if the key is not found.

#### (c *Config) ListKeys() ([]string, error)
Returns a list of all available keys (decrypted).

#### (c *Config) Delete(key string) error
Removes a key-value pair from the configuration.

## Security

### Encryption Details
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits
- **Key Storage**: Encrypted key stored alongside data
- **Nonce**: Unique nonce generated for each encryption operation

### Key Management
The encryption key is automatically generated when you first create a configuration. The key is:
- Stored encrypted in the same file as your data
- Never exposed in plain text
- Unique per configuration file

### Best Practices
1. **File Permissions**: Keep config files readable only by the owner (`0600`)
2. **Backup**: Regularly backup your configuration files
3. **Environment Separation**: Use different config files for different environments
4. **Access Control**: Limit who can read the configuration files
5. **Binary Security**: The binary format makes it much harder to identify and attack encrypted data

## File Storage

Configuration data is stored in a secure binary format that includes:

- **Magic Header**: "SCFG" identifier for file type recognition
- **Version Information**: Format version for future compatibility
- **Encrypted Key-Value Pairs**: All data is AES-256-GCM encrypted
- **Length-Prefixed Entries**: Each entry includes length information for parsing

The binary format provides several security advantages:
- **Not Human-Readable**: Cannot be easily inspected with text editors
- **Structure Obfuscation**: No visible JSON structure to exploit
- **Metadata Protection**: Entry lengths and structure are not exposed
- **Attack Resistance**: Much harder to identify encrypted content

The file is created automatically in:
1. Current working directory (if writable)
2. `~/.config/secureconfig/` (Unix-like systems)
3. Current directory (fallback)

## Examples

### Database Configuration
```go
config, _ := secureconfig.NewConfig()

// Store database credentials
config.Store("db.host", "localhost")
config.Store("db.port", "5432")
config.Store("db.username", "myuser")
config.Store("db.password", "secretpassword")
config.Store("db.database", "myapp")

// Retrieve in your application
host, _ := config.Retrieve("db.host")
password, _ := config.Retrieve("db.password")
```

### API Keys
```go
config.Store("api.stripe.secret_key", "sk_live_...")
config.Store("api.stripe.webhook_secret", "whsec_...")

// Use in your code
stripeKey, _ := config.Retrieve("api.stripe.secret_key")
```

### Environment Variables Alternative
```go
// Instead of environment variables, use encrypted config
config.Store("JWT_SECRET", "your-super-secret-jwt-key")
config.Store("SENDGRID_API_KEY", "SG.xxx")

jwtSecret, _ := config.Retrieve("JWT_SECRET")
```

## Error Handling

The package returns descriptive errors for common issues:

```go
value, err := config.Retrieve("nonexistent.key")
if err != nil {
    fmt.Println("Key not found:", err)
}

err = config.Store("", "value")
if err != nil {
    fmt.Println("Empty key not allowed:", err)
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security Considerations

- **Binary Format Security**: The binary storage format makes it much harder to identify and attack encrypted data compared to JSON
- **No Plain Text Exposure**: Configuration structure and metadata are not visible in the binary format
- **Obfuscated Content**: Encrypted data appears as random bytes, not recognizable base64 strings
- This package is suitable for local application configuration
- For production systems with multiple users, consider using dedicated secret management services
- Regularly rotate your encryption keys
- Keep configuration files secure and backed up
- Monitor access to configuration files
