// Package torembed runs the embedded tor executable. It stages the tor
// binary and geoip files into a fresh temp directory, starts tor through
// bine with a control connection, and hands out circuit-isolated SOCKS
// dialers (distinct username:password => distinct circuit, never shared
// between purposes).
package torembed

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"anonssh/internal/embed"

	"github.com/cretz/bine/control"
	"github.com/cretz/bine/process"
	"github.com/cretz/bine/tor"
	"golang.org/x/net/proxy"
)

// Runner is a live tor instance.
type Runner struct {
	Tor       *tor.Tor
	TempDir   string
	cmdCancel context.CancelFunc
}

// Start stages the embedded tor and boots it. debugWriter receives tor's
// stderr (bootstrap lines). geoip enables country-based exit selection.
// stateDir != nil keeps tor state (guards, consensus) between runs;
// otherwise a fresh temp dir is used per run and wiped on Close.
func Start(ctx context.Context, debugWriter io.Writer, geoip bool, stateDir *string, extraArgs []string) (*Runner, error) {
	if err := embed.VerifyAll(); err != nil {
		return nil, fmt.Errorf("embedded binaries integrity: %w", err)
	}
	torBytes, err := embed.TorBytes()
	if err != nil {
		return nil, fmt.Errorf("tor not embedded for %s/%s: %w", runtime.GOOS, runtime.GOARCH, embed.ErrNotEmbedded)
	}

	base, err := os.MkdirTemp("", "anonssh-tor-")
	if err != nil {
		return nil, err
	}
	r := &Runner{TempDir: base}
	cleanup := func() { os.RemoveAll(base) }

	exeName := "tor"
	if runtime.GOOS == "windows" {
		exeName = "tor.exe"
	}
	exePath := filepath.Join(base, exeName)
	if err := os.WriteFile(exePath, torBytes, 0o700); err != nil {
		cleanup()
		return nil, err
	}
	if runtime.GOOS != "windows" { // exec bit on unix
		os.Chmod(exePath, 0o700)
	}

	dataDir := base
	if stateDir != nil && *stateDir != "" {
		if err := os.MkdirAll(*stateDir, 0o700); err != nil {
			cleanup()
			return nil, err
		}
		dataDir = *stateDir
	}

	conf := &tor.StartConf{
		// Stage to disk and exec: embed + write + NewCreator. The binary
		// lives only in the per-run temp dir and is wiped on Close.
		ProcessCreator:    process.NewCreator(exePath),
		EnableNetwork:     true,
		DataDir:           dataDir,
		ExtraArgs:         extraArgs,
		DebugWriter:       debugWriter,
		TempDataDirBase:   base,
		RetainTempDataDir: stateDir != nil && *stateDir != "",
	}
	if geoip {
		conf.GeoIPFileReader = func(ipv6 bool) (io.ReadCloser, error) {
			b, err := embed.GeoIPBytes(ipv6)
			if err != nil {
				return nil, err
			}
			return io.NopCloser(bytes.NewReader(b)), nil
		}
	}

	t, err := tor.Start(ctx, conf)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("tor start: %w", err)
	}
	r.Tor = t
	return r, nil
}

// Dialer returns a SOCKS dialer bound to its own isolated circuit. Two calls
// never share a circuit: tor's IsolateSOCKSAuth keys circuits on the SOCKS
// auth bytes, and the auth bytes are fresh random per call. This is the
// property that keeps directory lookups unlinkable to SSH traffic.
func (r *Runner) Dialer(ctx context.Context) (*tor.Dialer, error) {
	u := make([]byte, 8)
	if _, err := rand.Read(u); err != nil {
		return nil, err
	}
	p := make([]byte, 8)
	if _, err := rand.Read(p); err != nil {
		return nil, err
	}
	return r.Tor.Dialer(ctx, &tor.DialConf{
		ProxyAuth: &proxy.Auth{
			User:     hex.EncodeToString(u),
			Password: hex.EncodeToString(p),
		},
	})
}

// SetConf applies control-port configuration (ExitNodes, StrictNodes, ...).
func (r *Runner) SetConf(kv ...string) error {
	entries := make([]*control.KeyVal, 0, len(kv))
	for i := 0; i+1 < len(kv); i += 2 {
		entries = append(entries, &control.KeyVal{Key: kv[i], Val: kv[i+1]})
	}
	return r.Tor.Control.SetConf(entries...)
}

// Exit publishes the control signal for tor to build a new general-purpose
// circuit (used after changing ExitNodes to force rebuilds).
func (r *Runner) ExitSignal() error {
	return r.Tor.Control.Signal("NEWNYM")
}

// Close stops tor and wipes the staging directory unless state was retained.
func (r *Runner) Close() {
	if r.Tor != nil {
		r.Tor.Close()
		r.Tor = nil
	}
	os.RemoveAll(r.TempDir)
}
