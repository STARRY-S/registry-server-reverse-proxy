package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// ServerURL is the URL of this registry server, used for redirecting
	// and location header
	ServerURL string `json:"serverURL" yaml:"serverURL"`
	// BindAddr is the address to bind, default 127.0.0.1
	BindAddr string `json:"bindAddr" yaml:"bindAddr"`
	// Port is the port of the proxy server
	Port int `json:"listen" yaml:"listen"`

	// TLS Certificate keypair
	Cert string `json:"cert" yaml:"cert"`
	Key  string `json:"key" yaml:"key"`

	// RemoteURL is the remote URL of the registry server to be proxied
	RemoteURL string `json:"remoteURL" yaml:"remoteURL"`

	// HookLocation, if true, will hook the location header to the registry server URL
	HookLocation bool `json:"hookLocation" yaml:"hookLocation"`

	// InsecureSkipTLSVerify, if true, will skip TLS verification for the proxied requests
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify" yaml:"insecureSkipTLSVerify"`

	Credential Credential `json:"credential" yaml:"credential"`

	Repositories []Repository `json:"repositories" yaml:"repositories"`

	// CustomRoutes is the list of other custom routes to be proxied
	CustomRoutes []Route `json:"customRoutes,omitempty" yaml:"customRoutes,omitempty"`
}

type Repository struct {
	// Name is the name of the repository
	Name    string `json:"name" yaml:"name"`
	Private bool   `json:"private" yaml:"private"`
}

type Credential struct {
	// Env Key, if set, will read credential from environment variables
	UsernameEnvKey string `json:"usernameEnvKey,omitempty" yaml:"usernameEnvKey,omitempty"`
	PasswordEnvKey string `json:"passwordEnvKey,omitempty" yaml:"passwordEnvKey,omitempty"`

	// Username is the username for the registry server
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	// Password is the password for the registry server
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
}

type Route struct {
	// Name is the name of the route
	Name string `json:"name,omitempty" yaml:"name,omitempty"`

	// Prefix matches the URL prefix to be proxied
	Prefix string `json:"prefix" yaml:"prefix"`

	// PlainText responses the txt data if Remote not set
	PlainText *PlainText `json:"plainText,omitempty" yaml:"plainText,omitempty"`

	// Static file responses the file content if Remote and PlainText not set
	StaticFile string `json:"staticFile,omitempty" yaml:"staticFile,omitempty"`
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
