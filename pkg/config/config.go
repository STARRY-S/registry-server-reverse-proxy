package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// BindAddr is the address to bind, default 127.0.0.1
	BindAddr string `json:"bindAddr" yaml:"bindAddr"`
	// Port is the port of the proxy server
	Port int `json:"listen" yaml:"listen"`

	// TLS Certificate keypair
	Cert string `json:"cert" yaml:"cert"`
	Key  string `json:"key" yaml:"key"`

	// InsecureSkipTLSVerify, if true, will skip TLS verification for the proxied requests
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify" yaml:"insecureSkipTLSVerify"`

	// Route is the
	Route []Route `json:"route" yaml:"route"`
}

type Route struct {
	// Name is the name of the route
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Prefix matches the URL prefix to be proxied
	Prefix string `json:"prefix" yaml:"prefix"`

	// Remote routes the remote route
	Remote *Remote `json:"remote,omitempty" yaml:"remote,omitempty"`

	// PlainText responses the txt data if Remote not set
	PlainText *PlainText `json:"plainText,omitempty" yaml:"plainText,omitempty"`

	// Static file responses the file content if Remote and PlainText not set
	StaticFile string `json:"staticFile,omitempty" yaml:"staticFile,omitempty"`
}

type Remote struct {
	// URL is the destination URL to be proxied
	URL string `json:"url,omitempty" yaml:"url,omitempty"`

	HookLocation bool `json:"hookLocation,omitempty" yaml:"hookLocation,omitempty"`
}

type PlainText struct {
	// Content is the plaintext content to be response
	Content string `json:"content,omitempty" yaml:"content,omitempty"`

	// Status is the status code of the plaintext response
	Status int `json:"status,omitempty" yaml:"status,omitempty"`
}

func NewConfigFromFile(name string) (*Config, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", name, err)
	}
	c := &Config{}
	err = yaml.Unmarshal(b, c)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config YAML %q: %w", name, err)
	}
	return c, nil
}
