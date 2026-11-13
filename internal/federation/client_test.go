package federation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHubOrigin(t *testing.T) {
	for _, tt := range []struct {
		input string
		valid bool
	}{
		{"https://hub.example/prefix", true}, {"http://127.0.0.1:1234/av", true},
		{"http://hub.example/av", false}, {"https://u:p@hub.example/av", false},
		{"https://hub.example/av?x=1", false}, {"https://hub.example/av?", false}, {"https://hub.example/av#x", false}, {"https://hub.example/av#", false},
	} {
		t.Run(tt.input, func(t *testing.T) {
			_, err := ParseHubOrigin(tt.input)
			if tt.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestHandshakeUsesPinnedBasePath(t *testing.T) {
	var path, authorization, archive string
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		authorization = r.Header.Get("Authorization")
		archive = r.Header.Get(SpokeArchiveHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hub_archive_id":"hub-a","protocol_versions":[1],"enrollment_uid":"enr-a","member":"member-a","policy":{},"policy_digest":"digest"}`))
	}))
	t.Cleanup(hub.Close)
	result, err := Handshake(t.Context(), hub.URL+"/av", "avfc_test", "spoke-a")
	require.NoError(t, err)
	assert.Equal(t, "/av/api/v1/federation/handshake", path)
	assert.Equal(t, "Bearer avfc_test", authorization)
	assert.Equal(t, "spoke-a", archive)
	assert.Equal(t, "hub-a", result.HubArchiveID)
}

func TestHandshakeRefusesRedirect(t *testing.T) {
	for _, code := range []int{301, 302, 307, 308} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			reached := false
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
			t.Cleanup(target.Close)
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, code) }))
			t.Cleanup(hub.Close)
			_, err := Handshake(t.Context(), hub.URL, "avfc_test", "spoke-a")
			require.Error(t, err)
			assert.False(t, reached)
		})
	}
}
