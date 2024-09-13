package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/adrg/xdg"
)

type Config struct {
	Token         string `json:"token"`
	EncryptionKey string `json:"encryption_key"`
}

func (c *Config) EncryptionKeyBytes() ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(c.EncryptionKey)
	if err != nil {
		return nil, err
	}
	return key, err
}

func (c *Config) SetEncryptionKey(key []byte) {
	keyString := base64.StdEncoding.EncodeToString(key)
	c.EncryptionKey = keyString
}

// opens or creates a config file at the default xdg path
func OpenDefaultConfigFile() (*os.File, error) {
	configFilePath, err := xdg.ConfigFile("bbfs-cli-config.json")
	if err != nil {
		return nil, err
	}

	configFile, err := os.OpenFile(configFilePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	return configFile, err

}

func ReadConfig(configFile *os.File) (*Config, error) {
	configStat, err := configFile.Stat()
	if err != nil {
		return nil, err
	}
	configBin := make([]byte, configStat.Size())
	n, err := configFile.Read(configBin)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	var config Config
	err = json.Unmarshal(configBin[:n], &config)
	if err != nil {
		return nil, err
	}

	return &config, err
}

func WriteConfigToFile(configFile *os.File, config *Config) error {
	configJson, err := json.Marshal(config)
	if err != nil {
		return err
	}

	_, err = configFile.Seek(0, 0)
	if err != nil {
		return err
	}
	err = configFile.Truncate(0)
	if err != nil {
		return err
	}
	_, err = configFile.Write(configJson)
	if err != nil {
		return err
	}

	return nil
}
