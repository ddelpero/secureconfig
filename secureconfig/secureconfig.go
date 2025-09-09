package secureconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

// ConfigFile is the default configuration file name
const ConfigFile = "secureconfig.json"

// Config holds the encryption configuration and data
type Config struct {
	ConfigFile string
	Key        []byte
	GCM        cipher.AEAD
	DB         map[string]interface{}
}

// NewConfig creates a new secure configuration instance
func NewConfig() (*Config, error) {
	return NewConfigWithFile(ConfigFile)
}

// NewConfigWithFile creates a new secure configuration instance with custom file
func NewConfigWithFile(filename string) (*Config, error) {
	c := &Config{
		ConfigFile: filename,
		DB:         make(map[string]interface{}),
	}

	configPath := findDataFile(c.ConfigFile)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Generate new key if config doesn't exist
		key := make([]byte, 32) // 256-bit key for AES-256
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("failed to generate key: %v", err)
		}
		c.DB["k"] = base64.StdEncoding.EncodeToString(key)
		if err := c.writeSecretsFile(); err != nil {
			return nil, err
		}
	}

	if err := c.loadDB(); err != nil {
		return nil, err
	}

	// Decode the key from base64
	keyStr, ok := c.DB["k"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid key format in database")
	}

	key, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %v", err)
	}
	c.Key = key

	// Initialize AES-GCM cipher
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}
	c.GCM = gcm

	return c, nil
}

// Store encrypts and stores a key-value pair
func (c *Config) Store(key, value string) error {
	encKey, err := c.Encrypt(key)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %v", err)
	}

	encValue, err := c.Encrypt(value)
	if err != nil {
		return fmt.Errorf("failed to encrypt value: %v", err)
	}

	c.DB[encKey] = encValue
	return c.writeSecretsFile()
}

// Retrieve decrypts and returns a value by key
func (c *Config) Retrieve(key string) (string, error) {
	for k, v := range c.DB {
		if k != "k" {
			decKey, err := c.Decrypt(k)
			if err != nil {
				continue // Skip invalid entries
			}
			if decKey == key {
				valueStr, ok := v.(string)
				if !ok {
					continue // Skip non-string values
				}
				return c.Decrypt(valueStr)
			}
		}
	}
	return "", fmt.Errorf("key not found: %s", key)
}

// Encrypt encrypts a string using AES-GCM
func (c *Config) Encrypt(value string) (string, error) {
	nonce := make([]byte, c.GCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := c.GCM.Seal(nonce, nonce, []byte(value), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a string using AES-GCM
func (c *Config) Decrypt(value string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	nonceSize := c.GCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := c.GCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	return string(plaintext), nil
}

// ListKeys returns all available keys (decrypted)
func (c *Config) ListKeys() ([]string, error) {
	var keys []string
	for k := range c.DB {
		if k != "k" {
			decKey, err := c.Decrypt(k)
			if err != nil {
				continue // Skip invalid entries
			}
			keys = append(keys, decKey)
		}
	}
	return keys, nil
}

// Delete removes a key-value pair
func (c *Config) Delete(key string) error {
	for k := range c.DB {
		if k != "k" {
			decKey, err := c.Decrypt(k)
			if err != nil {
				continue
			}
			if decKey == key {
				delete(c.DB, k)
				return c.writeSecretsFile()
			}
		}
	}
	return fmt.Errorf("key not found: %s", key)
}

func (c *Config) loadDB() error {
	filename := findDataFile(c.ConfigFile)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	if err := json.Unmarshal(data, &c.DB); err != nil {
		return fmt.Errorf("failed to unmarshal config: %v", err)
	}

	return nil
}

func (c *Config) writeSecretsFile() error {
	filename := findDataFile(c.ConfigFile)

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	data, err := json.MarshalIndent(c.DB, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := ioutil.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// findDataFile finds the appropriate location for the config file
func findDataFile(filename string) string {
	// Check current directory first
	if _, err := os.Stat(filename); err == nil {
		return filename
	}

	// Check user's home directory
	homeDir, err := os.UserHomeDir()
	if err == nil {
		homePath := filepath.Join(homeDir, ".config", "secureconfig", filename)
		// Try to create the directory
		os.MkdirAll(filepath.Dir(homePath), 0755)
		return homePath
	}

	// Fallback to current directory
	return filename
}
