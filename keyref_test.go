package main

import (
	"strings"
	"testing"

	v3 "github.com/exoscale/egoscale/v3"
)

func TestParseKeyRef(t *testing.T) {
	const id = "6b3f1c8e-2a4d-4e5f-9a1b-3c7d8e9f0a12"

	tests := []struct {
		name         string
		ref          string
		defaultZone  string
		wantEndpoint v3.Endpoint
		wantErr      string
	}{
		{name: "zone in reference", ref: "ch-gva-2/" + id, wantEndpoint: "https://api-ch-gva-2.exoscale.com/v2"},
		{name: "zone from default", ref: "/" + id, defaultZone: "de-fra-1", wantEndpoint: "https://api-de-fra-1.exoscale.com/v2"},
		{name: "reference zone wins", ref: "ch-gva-2/" + id, defaultZone: "de-fra-1", wantEndpoint: "https://api-ch-gva-2.exoscale.com/v2"},
		{name: "uppercase zone kept", ref: "CH-GVA-2/" + id, wantEndpoint: "https://api-CH-GVA-2.exoscale.com/v2"},
		{name: "unknown zone passes", ref: "xx-nope-1/" + id, wantEndpoint: "https://api-xx-nope-1.exoscale.com/v2"},
		{name: "single character zone", ref: "a/" + id, wantEndpoint: "https://api-a.exoscale.com/v2"},
		{name: "no zone", ref: "/" + id, wantErr: "EXOSCALE_ZONE is not set"},
		{name: "no slash", ref: id, wantErr: "invalid key reference"},
		{name: "extra segment", ref: "ch-gva-2/" + id + "/extra", wantErr: "invalid key reference"},
		{name: "empty uuid", ref: "ch-gva-2/", wantErr: "invalid key UUID"},
		{name: "alias", ref: "alias/foo", wantErr: "invalid key UUID"},
		{name: "leading dash", ref: "-ch-gva-2/" + id, wantErr: "invalid zone"},
		{name: "trailing dash", ref: "ch-gva-2-/" + id, wantErr: "invalid zone"},
		{name: "only dash", ref: "-/" + id, wantErr: "invalid zone"},
		{name: "dot", ref: "evil.example/" + id, wantErr: "invalid zone"},
		{name: "at sign", ref: "user@evil/" + id, wantErr: "invalid zone"},
		{name: "too long", ref: strings.Repeat("a", 64) + "/" + id, wantErr: "invalid zone"},
		{name: "invalid default zone", ref: "/" + id, defaultZone: "evil.example:443", wantErr: "invalid zone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, keyID, err := parseKeyRef(tt.ref, tt.defaultZone)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if endpoint != tt.wantEndpoint {
				t.Errorf("endpoint = %q, want %q", endpoint, tt.wantEndpoint)
			}
			if keyID != id {
				t.Errorf("keyID = %q, want %q", keyID, id)
			}
		})
	}
}
