package handlers

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"missing", "", ""},
		{"bearer", "Bearer abc.def.ghi", "abc.def.ghi"},
		{"bearer case-insensitive", "bearer abc.def.ghi", "abc.def.ghi"},
		{"bearer trims whitespace", "Bearer   abc.def.ghi  ", "abc.def.ghi"},
		{"basic with jwt in password", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:abc.def.ghi")), "abc.def.ghi"},
		{"basic with empty username", "Basic " + base64.StdEncoding.EncodeToString([]byte(":abc.def.ghi")), "abc.def.ghi"},
		{"basic without colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("noseparator")), ""},
		{"basic invalid base64", "Basic !!!not-base64!!!", ""},
		{"unknown scheme", "Digest abc", ""},
		{"no space", "Bearer", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			if got := extractBearerToken(r); got != tc.want {
				t.Errorf("extractBearerToken() = %q, want %q", got, tc.want)
			}
		})
	}
}
