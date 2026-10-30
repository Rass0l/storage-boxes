package enrichment

import "testing"

func TestDefaultCountryLookupClassifiesReserved(t *testing.T) {
	l := DefaultCountryLookup{}
	cases := []struct {
		ip, want string
	}{
		{"127.0.0.1", "LO"},
		{"::1", "LO"},
		{"10.0.0.42", "PR"},
		{"192.168.1.7", "PR"},
		{"172.17.4.3", "PR"},
		{"fd00::1", "PR"},
		{"169.254.10.10", "PR"}, // link-local
		{"8.8.8.8", ""},
		{"203.0.113.1", ""},
		{"not-an-ip", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := l.Lookup(tc.ip)
			if got != tc.want {
				t.Fatalf("Lookup(%q): want %q, got %q", tc.ip, tc.want, got)
			}
		})
	}
}

func TestStaticCountryLookupFallsBack(t *testing.T) {
	l := StaticCountryLookup{
		Table:    map[string]string{"203.0.113.42": "US"},
		Fallback: "??",
	}
	if got := l.Lookup("203.0.113.42"); got != "US" {
		t.Fatalf("want US, got %q", got)
	}
	if got := l.Lookup("198.51.100.1"); got != "??" {
		t.Fatalf("want ??, got %q", got)
	}
}
