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

		RedirectBlobsLocation: RedirectBlobsLocation{
			Enabled: true, // Enable redirect blobs to CDN cached URL
			URL:     "https://cdn-blobs.example.com",
			AuthConfig: CDNAuthConfig{
				TokenEnvKey: "BLOBS_CDN_AUTH_TOKEN", // ENV Key for auth token
			},
		},
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
				Path: "/",
				PlainText: &PlainText{
					Content: "Hello World\n",
					Status:  200,
				},
			},
			{
				Prefix: "/text",
				PlainText: &PlainText{
					Content: "This is a plain text response\n",
					Status:  200,
				},
			},
			{
				Prefix:     "/favicon.ico",
				StaticFile: "static/favicon.ico",
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
