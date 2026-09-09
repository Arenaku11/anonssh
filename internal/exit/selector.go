// Package exit provides Onionoo-based exit node selection for Tor.
package exit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

// Relay holds the subset of an Onionoo relay document we need.
type Relay struct {
	Nickname    string   `json:"nickname"`
	ORAddresses []string `json:"or_addresses"`
	ExitPolicy  string   `json:"exit_policy_summary"`
	Country     string   `json:"country"`
	CountryName string   `json:"country_name"`
	Fingerprint string   `json:"fingerprint"`
}

// Selector queries Onionoo for relays whose exit policy allows the given port.
type Selector struct {
	client *http.Client
}

// New returns a Selector with a 15-second HTTP timeout.
func New() *Selector {
	return &Selector{client: &http.Client{Timeout: 15 * time.Second}}
}

// Pick returns a random relay that allows exiting to targetPort from one of
// the allowedCountries (empty = any country). Uses the Onionoo details endpoint.
func (s *Selector) Pick(ctx context.Context, targetPort int, allowedCountries []string) (*Relay, error) {
	url := "https://onionoo.torproject.org/details?running=true&flag=Exit&fields=nickname,or_addresses,exit_policy_summary,country,country_name,fingerprint"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("onionoo request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("onionoo fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("onionoo %d: %s", resp.StatusCode, string(b[:min(len(b), 200)]))
	}
	var doc struct {
		Relays []Relay `json:"relays"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("onionoo decode: %w", err)
	}

	countrySet := make(map[string]bool, len(allowedCountries))
	for _, c := range allowedCountries {
		countrySet[strings.ToUpper(c)] = true
	}

	var candidates []Relay
	for _, r := range doc.Relays {
		if !policyAllowsPort(r.ExitPolicy, targetPort) {
			continue
		}
		if len(countrySet) > 0 && !countrySet[strings.ToUpper(r.Country)] {
			continue
		}
		// Must have an IPv4 ORAddress for use as exit.
		hasV4 := false
		for _, addr := range r.ORAddresses {
			// IPv4 addresses don't start with '[' (which marks IPv6).
			if !strings.HasPrefix(addr, "[") {
				hasV4 = true
				break
			}
		}
		if !hasV4 {
			continue
		}
		candidates = append(candidates, r)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no exit relay found for port %d (countries=%v)", targetPort, allowedCountries)
	}
	return &candidates[rand.IntN(len(candidates))], nil
}

// policyAllowsPort checks if the exit_policy_summary mentions the port in its
// accept list. Onionoo format: {"accept":["80","443"],"reject":["25"]}
func policyAllowsPort(summary string, port int) bool {
	if summary == "" {
		return false
	}
	portStr := fmt.Sprintf("%d", port)
	idx := strings.Index(summary, portStr)
	if idx < 0 {
		return false
	}
	// Check it's in an "accept" section (not "reject").
	before := summary[:idx]
	lastAccept := strings.LastIndex(before, "accept")
	lastReject := strings.LastIndex(before, "reject")
	return lastAccept > lastReject
}
