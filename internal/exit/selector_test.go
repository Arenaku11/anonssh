package exit

import "testing"

func TestPolicyAllowsPort(t *testing.T) {
	tests := []struct {
		summary string
		port    int
		want    bool
	}{
		{`{"accept":["80","443"],"reject":["25"]}`, 80, true},
		{`{"accept":["80","443"],"reject":["25"]}`, 25, false},
		{`{"accept":["80","443"],"reject":["25"]}`, 443, true},
		{`{"accept":["1024-65535"]}`, 22, false},
		{`{"accept":["22","80","443"]}`, 22, true},
		{`{"accept":["22","80","443"]}`, 8080, false},
		{`{"reject":["0-65535"]}`, 80, false},
		{"", 80, false},
	}
	for _, tt := range tests {
		if got := policyAllowsPort(tt.summary, tt.port); got != tt.want {
			t.Errorf("policyAllowsPort(%q, %d) = %v, want %v", tt.summary, tt.port, got, tt.want)
		}
	}
}
