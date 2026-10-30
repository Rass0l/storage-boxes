package config

type RuntimeMode string

const (
	RuntimeAPI          RuntimeMode = "api"
	RuntimeWorker       RuntimeMode = "worker"
	RuntimeMigrate      RuntimeMode = "migrate"
	RuntimeShareGateway RuntimeMode = "share-gateway"
)
