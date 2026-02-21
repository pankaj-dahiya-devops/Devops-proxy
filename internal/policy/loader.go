package policy

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadPolicy(path string) (*PolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg PolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Version != 1 {
		return nil, errors.New("unsupported policy version")
	}

	if cfg.Domains == nil {
		cfg.Domains = make(map[string]DomainConfig)
	}

	if cfg.Rules == nil {
		cfg.Rules = make(map[string]RuleConfig)
	}

	return &cfg, nil
}