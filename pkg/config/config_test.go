package config

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func Test_Config(t *testing.T) {
	c := &Config{
		BindAddr: "127.0.0.1",
		Port:     8080,
		Cert:     "",
		Key:      "",

		InsecureSkipTLSVerify: false,
		Route: []Route{
			{
				Name:   "registry-server",
				Prefix: "/v2",
				Remote: &Remote{
					URL:          "http://registry.example.com",
					HookLocation: true,
				},
			},
			{
				Prefix: "/",
				PlainText: &PlainText{
					Content: "This is a plain text response",
					Status:  200,
				},
			},
			{
				Prefix: "/favicon.ico",
				PlainText: &PlainText{
					Content: "404 not found",
					Status:  404,
				},
			},
		},
	}

	b, err := yaml.Marshal(c)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	f, err := os.Create("tmp.yaml")
	if err != nil {
		t.Fatalf("failed to create tmp.yaml: %v", err)
	}
	defer f.Close()
	f.Write(b)
}
