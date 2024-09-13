package config

import "os"

func FileServerBaseURL() string {
	if baseURL := os.Getenv("FILE_SERVER_BASE_URL"); baseURL != "" {
		return baseURL
	} else {
		return "big-file-server.fly.dev:9998"
	}
}

func FileServerHTTPS() bool {
	switch os.Getenv("FILE_SERVER_HTTPS") {
	case "true", "1":
		return true
	case "false", "0":
		return false
	default:
		return true
	}
}

func BigCentralBaseURL() string {
	if baseURL := os.Getenv("BIG_CENTRAL_BASE_URL"); baseURL != "" {
		return baseURL
	} else {
		return "https://bbfs.io"
	}
}
