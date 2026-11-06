package main

import (
	"errors"
	"fmt"
	"strings"

	v3 "github.com/exoscale/egoscale/v3"
)

// parseKeyRef parses "<zone>/<key-uuid>" as cosign passes it, using defaultZone when the zone is empty.
func parseKeyRef(ref, defaultZone string) (v3.Endpoint, v3.UUID, error) {
	zone, id, ok := strings.Cut(ref, "/")
	if !ok || strings.Contains(id, "/") {
		return "", "", fmt.Errorf("invalid key reference %q, want exoscalekms://<zone>/<key-uuid> or exoscalekms:///<key-uuid>", ref)
	}
	keyID, err := v3.ParseUUID(id)
	if err != nil {
		return "", "", fmt.Errorf("invalid key UUID %q: %w", id, err)
	}
	if zone == "" {
		if defaultZone == "" {
			return "", "", errors.New("no zone in key reference and EXOSCALE_ZONE is not set")
		}
		zone = defaultZone
	}
	if !isValidZone(zone) {
		return "", "", fmt.Errorf("invalid zone %q", zone)
	}
	return v3.Endpoint("https://api-" + zone + ".exoscale.com/v2"), keyID, nil
}

// isValidZone reports whether zone is 1 to 63 letters, digits or dashes without a leading or trailing dash, like the AWS SDK region check.
func isValidZone(zone string) bool {
	if l := len(zone); l == 0 || l > 63 || zone[0] == '-' || zone[l-1] == '-' {
		return false
	}
	for _, r := range zone {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-':
		default:
			return false
		}
	}
	return true
}
