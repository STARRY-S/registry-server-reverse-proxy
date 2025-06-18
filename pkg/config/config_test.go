package config

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func Test_Config(t *testing.T) {
	c := &Config{
		ServerURL: "http://registry.abc.local:8080",
		BindAddr:  "127.0.0.1",
		Port:      8080,
		CertFile:  "",
		KeyFile:   "",

		RemoteURL:             "http://registry.example.com",
		InsecureSkipTLSVerify: false,
		// Example repositories
		Repositories: []Repository{
			{
				Name:    "library",
				Private: false,
			},
			{
				Name:    "test1",
				Private: true,
			},
			{
				Name:    "test2",
				Private: true,
			},
		},
		CustomRoutes: []Route{
			{
				Prefix: "/text",
				PlainText: &PlainText{
					Content: "This is a plain text response\n",
					Status:  200,
				},
			},
			{
				Prefix: "/favicon.ico",
				PlainText: &PlainText{
					Content: "404 not found\n",
					Status:  404,
				},
			},
		},
	}

	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	f, err := os.Create("config.yaml")
	if err != nil {
		t.Fatalf("failed to create tmp.yaml: %v", err)
	}
	defer f.Close()
	f.Write(b)
}
