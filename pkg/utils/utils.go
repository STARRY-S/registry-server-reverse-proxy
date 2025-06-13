package utils

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/STARRY-S/simple-logrus-formatter/pkg/formatter"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"golang.org/x/term"
)

const (
	// Sleep interval to avoid rate-limit.
	DefaultInterval = time.Millisecond * 300
)

func SetupLogrus() {
	formatter := &formatter.Formatter{}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		// Disable if the output is not terminal.
		formatter.NoColors = true
	}
	logrus.SetFormatter(formatter)
	logrus.SetOutput(io.Discard)
	logrus.AddHook(&writer.Hook{
		// Send logs with level higher than warning to stderr.
		Writer: os.Stderr,
		LogLevels: []logrus.Level{
			logrus.PanicLevel,
			logrus.FatalLevel,
			logrus.ErrorLevel,
			logrus.WarnLevel,
		},
	})
	logrus.AddHook(&writer.Hook{
		// Send info, debug and trace logs to stdout.
		Writer: os.Stdout,
		LogLevels: []logrus.Level{
			logrus.TraceLevel,
			logrus.InfoLevel,
			logrus.DebugLevel,
		},
	})
}

func Print(a any) string {
	b, _ := json.MarshalIndent(a, "", "  ")
	return string(b)
}

func PrintNoIndent(a any) string {
	b, _ := json.Marshal(a)
	return string(b)
}

type valueTypes interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 |
		~uint32 | ~uint64 | ~uintptr | ~float32 | ~float64 | ~string | ~bool |
		[]string
}

// Pointer gets the pointer of the variable.
func Pointer[T valueTypes](i T) *T {
	return &i
}

// A safe function to get the value from the pointer.
func Value[T valueTypes](p *T) T {
	if p == nil {
		return *new(T)
	}
	return *p
}

func Scanf(ctx context.Context, format string, a ...any) (int, error) {
	nCh := make(chan int)
	go func() {
		n, _ := fmt.Scanf(format, a...)
		nCh <- n
	}()
	select {
	case n := <-nCh:
		return n, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func CheckFileExistsPrompt(
	ctx context.Context, name string, autoYes bool,
) error {
	_, err := os.Stat(name)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	var s string
	fmt.Printf("File %q already exists! Overwrite? [y/N] ", name)
	if autoYes {
		fmt.Println("y")
	} else {
		if _, err := Scanf(ctx, "%s", &s); err != nil {
			return err
		}
		if len(s) == 0 || s[0] != 'y' && s[0] != 'Y' {
			return fmt.Errorf("file %q already exists", name)
		}
	}

	return nil
}

func MatchFilters(s string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	if s == "" {
		// Ignore no-name instance
		return false
	}
	for _, f := range filters {
		if strings.Contains(s, f) {
			return true
		}
	}
	return false
}

func HttpGet(ctx context.Context, u string, insecure bool) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		log.Fatalf("%v", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		},
		Timeout: time.Hour * 5,
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get http request on %q: %w", u, err)
	}
	return res, nil
}

var (
	// https://127.0.0.1:5000/v2/library/NAME/manifests/latest
	manifestURLRegex = regexp.MustCompile(`^/v2/([^/]+)/([^/]+)/manifests/([^/]+)$`)
	// https://127.0.0.1:5000/v2/library/NAME/blobs/sha256:aabbccdd....
	blobsURLRegex = regexp.MustCompile(`^/v2/([^/]+)/([^/]+)/blobs/([^/]+)$`)
)

func DetectURLType(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	if manifestURLRegex.Match([]byte(u.Path)) {
		return "manifest"
	} else if blobsURLRegex.Match([]byte(u.Path)) {
		return "blobs"
	}
	return ""
}
