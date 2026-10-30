package main

import "github.com/Rass0l/storage-boxes/internal/platform/config"

func loadRuntimeConfig() (config.Config, error) {
	return config.Load()
}
