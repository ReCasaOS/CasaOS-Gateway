package common

import (
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/ReCasaOS/CasaOS-Common/utils/constants"
)

const (
	ConfigKeyLogPath     = "gateway.LogPath"
	ConfigKeyLogSaveName = "gateway.LogSaveName"
	ConfigKeyLogFileExt  = "gateway.LogFileExt"
	ConfigKeyGatewayPort = "gateway.Port"
	// Interface the public gateway port binds to. Empty, the default, binds
	// every interface (dual-stack [::]), which is what CasaOS has always done.
	ConfigKeyGatewayAddress = "gateway.Address"
	// Both must be set for the gateway to serve HTTPS. Left empty, it serves
	// plain HTTP, which is the default and what CasaOS has always done.
	ConfigKeyGatewayTLSCert = "gateway.TLSCert"
	ConfigKeyGatewayTLSKey  = "gateway.TLSKey"
	// The port HTTPS is served on with a certificate the gateway makes for
	// itself, when no certificate is supplied above. Empty is the default,
	// 443; "0" turns it off.
	ConfigKeyGatewayHTTPSPort = "gateway.HTTPSPort"
	ConfigKeyRuntimePath    = "common.RuntimePath"

	GatewayName       = "gateway"
	GatewayConfigType = "ini"
)

func LoadConfig() (*viper.Viper, error) {
	config := viper.New()

	config.SetDefault(ConfigKeyLogPath, constants.DefaultLogPath)
	config.SetDefault(ConfigKeyLogSaveName, GatewayName)
	config.SetDefault(ConfigKeyLogFileExt, "log")

	config.SetDefault(ConfigKeyRuntimePath, constants.DefaultRuntimePath) // See https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch05s13.html

	config.SetConfigName(GatewayName)
	config.SetConfigType(GatewayConfigType)

	if currentDirectory, err := os.Getwd(); err != nil {
		log.Println(err)
	} else {
		config.AddConfigPath(currentDirectory)
		config.AddConfigPath(filepath.Join(currentDirectory, "conf"))
	}

	if configPath, success := os.LookupEnv("CASAOS_CONFIG_PATH"); success {
		config.AddConfigPath(configPath)
	}

	config.AddConfigPath(constants.DefaultConfigPath)

	if err := config.ReadInConfig(); err != nil {
		return nil, err
	}

	return config, nil
}

func GatewayConfigFilePath() string {
	if p, ok := os.LookupEnv("CASAOS_CONFIG_PATH"); ok && p != "" {
		return filepath.Join(p, GatewayName+"."+GatewayConfigType)
	}
	return filepath.Join(constants.DefaultConfigPath, GatewayName+"."+GatewayConfigType)
}

func EnsureGatewayConfig(sample string) error {
	path := GatewayConfigFilePath()
	_, err := os.Stat(path)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(sample), 0o600)
}
