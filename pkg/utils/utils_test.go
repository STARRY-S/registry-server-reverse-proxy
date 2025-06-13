package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MatchFilters(t *testing.T) {
	type P struct {
		s       string
		filters []string
		result  bool
	}

	var cases = []P{
		{"abc", []string{}, true},
		{"autok3s.user-validation-1.ap-region-1.aws.master", []string{"abc"}, false},
		{"autok3s.user-validation-1.ap-region-1.aws.master", []string{"autok3s", "validation"}, true},
		{"auto-rancher-test-1", []string{"auto", "foo"}, true},
		{"", []string{}, true},
	}

	for _, c := range cases {
		t.Logf("s: %s, filters: %v, result: %v\n", c.s, c.filters, c.result)
		assert.Equal(t, c.result, MatchFilters(c.s, c.filters))
	}
}

func Test_DetectURLType(t *testing.T) {
	assert.Equal(t, "manifest", DetectURLType("/v2/library/nginx/manifests/latest"))
	assert.Equal(t, "manifest", DetectURLType("/v2/library/alpine/manifests/latest"))
	assert.Equal(t, "blobs", DetectURLType("/v2/library/nginx/blobs/sha256:abcabc"))
	assert.Equal(t, "manifest", DetectURLType("https://registry.abc.com/v2/library/nginx/manifests/latest"))
	assert.Equal(t, "blobs", DetectURLType("https://registry.abc.com/v2/library/nginx/blobs/sha256:abcabc"))
	assert.Equal(t, "", DetectURLType("https://registry.abc.com/v1"))
	assert.Equal(t, "", DetectURLType("https://registry.abc.com/v2/token"))
}
