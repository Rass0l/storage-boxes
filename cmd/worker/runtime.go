package main

import "github.com/Rass0l/storage-boxes/internal/platform/config"

func loadRuntimeConfig() (config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return config.Config{}, err
	}
	if err := cfg.ValidateMasterKey(true); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}
