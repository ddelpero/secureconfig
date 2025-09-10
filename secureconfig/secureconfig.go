package secureconfig

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ConfigFile is the default configuration file name
const ConfigFile = "config"

// Magic header to identify secureconfig files
const MagicHeader = "SCFG"
const Version = 1

// Config holds the encryption configuration and data
type Config struct {
	ConfigFile string
	Key        []byte
	GCM        cipher.AEAD
	DB         map[string]string
}

// NewConfig creates a new secure configuration instance
func NewConfig() (*Config, error) {
	return NewConfigWithFile(ConfigFile)
}

// NewConfigWithFile creates a new secure configuration instance with custom file
func NewConfigWithFile(filename string) (*Config, error) {
	c := &Config{
		ConfigFile: filename,
		DB:         make(map[string]string),
	}

	configPath := findDataFile(c.ConfigFile)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Generate new key if config doesn't exist
		key := make([]byte, 32) // 256-bit key for AES-256
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("failed to generate key: %v", err)
		}
		// Store key as hex string for binary format
		c.DB["k"] = fmt.Sprintf("%x", key)
		if err := c.writeSecretsFile(); err != nil {
			return nil, err
		}
	}

	if err := c.loadDB(); err != nil {
		return nil, err
	}

	// Decode the key from hex
	keyStr, ok := c.DB["k"]
	if !ok {
		return nil, fmt.Errorf("key not found in database")
	}

	// Parse hex key
	key := make([]byte, 32)
	if _, err := fmt.Sscanf(keyStr, "%x", &key); err != nil {
		return nil, fmt.Errorf("failed to parse key: %v", err)
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
	encKeyBytes, err := c.Encrypt(key)
	if err != nil {
		return fmt.Errorf("failed to encrypt key: %v", err)
	}
	encKey := base64.StdEncoding.EncodeToString(encKeyBytes)

	encValueBytes, err := c.Encrypt(value)
	if err != nil {
		return fmt.Errorf("failed to encrypt value: %v", err)
	}
	encValue := base64.StdEncoding.EncodeToString(encValueBytes)

	c.DB[encKey] = encValue
	return c.writeSecretsFile()
}

// Retrieve decrypts and returns a value by key
func (c *Config) Retrieve(key string) (string, error) {
	for k, v := range c.DB {
		if k != "k" {
			// Decode base64 key
			keyBytes, err := base64.StdEncoding.DecodeString(k)
			if err != nil {
				continue // Skip invalid entries
			}
			decKey, err := c.Decrypt(keyBytes)
			if err != nil {
				continue // Skip invalid entries
			}
			if decKey == key {
				// Decode base64 value
				valueBytes, err := base64.StdEncoding.DecodeString(v)
				if err != nil {
					continue // Skip invalid entries
				}
				return c.Decrypt(valueBytes)
			}
		}
	}
	return "", fmt.Errorf("key not found: %s", key)
}

// Encrypt encrypts a string using AES-GCM and returns raw bytes
func (c *Config) Encrypt(value string) ([]byte, error) {
	nonce := make([]byte, c.GCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	ciphertext := c.GCM.Seal(nonce, nonce, []byte(value), nil)
	return ciphertext, nil
}

// Decrypt decrypts raw bytes using AES-GCM
func (c *Config) Decrypt(data []byte) (string, error) {
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
			// Decode base64 key
			keyBytes, err := base64.StdEncoding.DecodeString(k)
			if err != nil {
				continue // Skip invalid entries
			}
			decKey, err := c.Decrypt(keyBytes)
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
			// Decode base64 key
			keyBytes, err := base64.StdEncoding.DecodeString(k)
			if err != nil {
				continue
			}
			decKey, err := c.Decrypt(keyBytes)
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
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %v", err)
	}

	// Check magic header
	if len(data) < 8 {
		return fmt.Errorf("file too short")
	}
	if string(data[:4]) != MagicHeader {
		return fmt.Errorf("invalid file format")
	}

	// Check version
	version := binary.BigEndian.Uint32(data[4:8])
	if version != Version {
		return fmt.Errorf("unsupported version: %d", version)
	}

	// Read number of entries
	offset := 8
	if len(data) < offset+4 {
		return fmt.Errorf("file too short for entry count")
	}
	numEntries := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	// Read entries
	c.DB = make(map[string]string)
	for i := uint32(0); i < numEntries; i++ {
		if len(data) < offset+4 {
			return fmt.Errorf("file too short for key length")
		}
		keyLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if len(data) < offset+int(keyLen) {
			return fmt.Errorf("file too short for key data")
		}
		key := string(data[offset : offset+int(keyLen)])
		offset += int(keyLen)

		if len(data) < offset+4 {
			return fmt.Errorf("file too short for value length")
		}
		valueLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if len(data) < offset+int(valueLen) {
			return fmt.Errorf("file too short for value data")
		}
		value := string(data[offset : offset+int(valueLen)])
		offset += int(valueLen)

		c.DB[key] = value
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

	var buf bytes.Buffer

	// Write magic header
	buf.WriteString(MagicHeader)

	// Write version
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, Version)
	buf.Write(versionBytes)

	// Write number of entries
	numEntries := uint32(len(c.DB))
	entryCountBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(entryCountBytes, numEntries)
	buf.Write(entryCountBytes)

	// Write entries
	for key, value := range c.DB {
		// Write key length
		keyLenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(keyLenBytes, uint32(len(key)))
		buf.Write(keyLenBytes)

		// Write key
		buf.WriteString(key)

		// Write value length
		valueLenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(valueLenBytes, uint32(len(value)))
		buf.Write(valueLenBytes)

		// Write value
		buf.WriteString(value)
	}

	// Write to file
	if err := os.WriteFile(filename, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}

// findDataFile finds the appropriate location for the config file
func findDataFile(filename string) string {
	fmt.Printf("Searching for config file: %s\n", filename)
	// Check current directory first
	if _, err := os.Stat(filename); err == nil {
		return filename
	}

	// Check user's home directory
	// homeDir, err := os.UserHomeDir()
	// if err == nil {
	// 	homePath := filepath.Join(homeDir, ".config", "secureconfig", filename)
	// 	// Try to create the directory
	// 	os.MkdirAll(filepath.Dir(homePath), 0755)
	// 	fmt.Printf("Using config file in home directory: %s\n", homePath)
	// 	return homePath
	// }

	// Fallback to current directory
	fmt.Printf("Falling back to current directory for config file\n")
	return filename
}
