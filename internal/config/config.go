package config

// Config holds all application configuration parsed from YAML.
type Config struct {
	Sources SourcesConfig `yaml:"sources"`
}

// SourcesConfig holds per-source configuration blocks.
// A nil pointer means the source was not mentioned in the config file;
// it does NOT mean the source is disabled.
type SourcesConfig struct {
	AWS *AWSConfig `yaml:"aws,omitempty"`
	// Future: GitHub *GitHubConfig `yaml:"github,omitempty"`
}

// AWSConfig holds AWS-specific settings declared in the config file.
type AWSConfig struct {
	Region string `yaml:"region,omitempty"`
}
