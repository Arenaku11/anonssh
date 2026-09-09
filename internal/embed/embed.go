// Package embed holds the binaries produced by the embed CI workflow and
// gives them to the runtime. Files are committed by CI (see
// .github/workflows/embed.yml) with a manifest of hashes; builds fail hard
// if the tree is missing them.
package embed

import (
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

// ManifestParsed reads manifest.txt. Keys are lowercase; hash lines appear
// as "sha256 <name> <hash>" flattened to "sha256:<name>" = "<hash>".
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
		if n, _ := fmt.Sscanf(line, "sha256 %s %s", &k, &v); n == 2 {
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

// VerifyAll checks that every bin/ file has a matching sha256 entry in the
// manifest. Called at startup; a mismatch means the committed tree and the
// manifest disagree, which is a build-integrity error, not a runtime one.
func VerifyAll() error {
	m, err := ManifestParsed()
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(content, "bin")
	if err != nil {
		return err
	}
	var missing []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if m["sha256:"+e.Name()] == "" {
			missing = append(missing, e.Name())
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("no manifest sha256 for: %v", missing)
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
