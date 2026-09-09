package sshcli

import "testing"

func TestNewSessionDefaults(t *testing.T) {
	s, err := NewSession(Options{User: "test"})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if s.Config.User != "test" {
		t.Errorf("user = %q, want test", s.Config.User)
	}
	if s.ClientVer == "" {
		t.Error("client version should not be empty")
	}
	if len(s.Config.Auth) == 0 {
		t.Error("expected at least one auth method")
	}
}

func TestBannerPool(t *testing.T) {
	seen := make(map[string]bool)
	for i := range bannerPool {
		seen[bannerPool[i]] = true
	}
	if len(seen) < 3 {
		t.Errorf("banner pool too small, only %d unique banners", len(seen))
	}
}

func TestNoRandomize(t *testing.T) {
	s, err := NewSession(Options{User: "test", NoRandomize: true})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if s.ClientVer != "SSH-2.0-Go" {
		t.Errorf("ClientVer = %q, want SSH-2.0-Go", s.ClientVer)
	}
}
