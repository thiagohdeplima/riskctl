package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Loader loads configuration.
type Loader interface {
	Load() (Config, error)
}

// ConfigLoader reads configuration from environment variables prefixed with RISKCTL_.
// For example, RISKCTL_SOURCES_AWS_REGION maps to sources.aws.region.
type ConfigLoader struct{}

func (l *ConfigLoader) Load() (Config, error) {
	var cfg Config

	v := viper.New()
	v.SetEnvPrefix("RISKCTL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Register known keys so AutomaticEnv can resolve them from environment.
	v.SetDefault("sources.aws.region", "")

	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}
