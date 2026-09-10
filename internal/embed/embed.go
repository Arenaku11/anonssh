// Package embed holds the binaries produced by the embed CI workflow and
// gives them to the runtime. Files are committed by CI (see
// .github/workflows/embed.yml) with a manifest of hashes; builds fail hard
// if the tree is missing them.
package embed

import (
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
)

//go:embed bin/* geoip/* manifest.txt
var content embed.FS

// Manifest is the parsed key=value set from manifest.txt.
type Manifest map[string]string

// ManifestParsed reads manifest.txt. Hash lines use sha256sum's output order:
// "sha256 <hash> <name>", flattened to "sha256:<name>" = "<hash>".
func ManifestParsed() (Manifest, error) {
	data, err := content.ReadFile("manifest.txt")
	if err != nil {
		return nil, err
	}
	m := Manifest{}
	for _, line := range splitLines(data) {
		if line == "" || line[0] == '#' {
			continue
		}
		var k, v string
		if n, _ := fmt.Sscanf(line, "sha256 %s %s", &v, &k); n == 2 {
			m["sha256:"+k] = v
			continue
		}
		if i := indexByte(line, '='); i > 0 {
			k, v = line[:i], line[i+1:]
			m[k] = v
		}
	}
	return m, nil
}

// TorBytes returns the embedded tor executable for the running platform.
func TorBytes() ([]byte, error) {
	name := fmt.Sprintf("bin/tor-%s-%s", runtime.GOOS, runtime.GOARCH)
	switch runtime.GOOS {
	case "windows":
		name += ".exe"
	}
	return fs.ReadFile(content, name)
}

// GeoIPBytes returns the country database (geoip or geoip6).
func GeoIPBytes(ipv6 bool) ([]byte, error) {
	if ipv6 {
		return fs.ReadFile(content, "geoip/geoip6")
	}
	return fs.ReadFile(content, "geoip/geoip")
}

// TransportBytes returns a pluggable transport client binary. Transport is
// "obfs4" or "snowflake".
func TransportBytes(transport string) ([]byte, error) {
	var name string
	switch transport {
	case "obfs4":
		name = fmt.Sprintf("bin/obfs4proxy-%s-%s", runtime.GOOS, runtime.GOARCH)
	case "snowflake":
		name = fmt.Sprintf("bin/snowflake-client-%s-%s", runtime.GOOS, runtime.GOARCH)
	default:
		return nil, fmt.Errorf("unknown transport %q", transport)
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return fs.ReadFile(content, name)
}

// VerifyAll checks every embedded binary against its manifest SHA256.
func VerifyAll() error {
	m, err := ManifestParsed()
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(content, "bin")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		want := m["sha256:"+e.Name()]
		if want == "" {
			return fmt.Errorf("no manifest sha256 for %s", e.Name())
		}
		data, err := content.ReadFile("bin/" + e.Name())
		if err != nil {
			return err
		}
		got := fmt.Sprintf("%x", sha256.Sum256(data))
		if got != want {
			return fmt.Errorf("sha256 mismatch for %s: got %s, want %s", e.Name(), got, want)
		}
	}
	return nil
}

// ErrNotEmbedded is returned when the running build lacks a binary (e.g.
// transports were not committed yet).
var ErrNotEmbedded = errors.New("binary not embedded in this build")

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			line := b[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			out = append(out, string(line))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
