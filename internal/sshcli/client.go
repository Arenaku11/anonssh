// Package sshcli provides an anonymous SSH client that routes through Tor
// SOCKS5 with ephemeral identities and randomized client banners.
package sshcli

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"fmt"
	"log"
	"net"
	"os"

	mrand "math/rand/v2"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

// bannerPool contains common OpenSSH client version strings. The client
// picks one at random per session to blend in with normal OpenSSH traffic.
var bannerPool = []string{
	"SSH-2.0-OpenSSH_9.6",
	"SSH-2.0-OpenSSH_9.5",
	"SSH-2.0-OpenSSH_9.3",
	"SSH-2.0-OpenSSH_9.2",
	"SSH-2.0-OpenSSH_8.9",
	"SSH-2.0-OpenSSH_8.8",
	"SSH-2.0-OpenSSH_8.7",
	"SSH-2.0-OpenSSH_8.4p1",
	"SSH-2.0-OpenSSH_9.7",
}

// Session holds state for one anonymous SSH connection.
type Session struct {
	Config     *ssh.ClientConfig
	ClientVer  string
	knownHosts map[string]ssh.PublicKey
}

// Options configures a session.
type Options struct {
	User        string
	Password    string // empty = no password auth
	KeyFile     string // path to user's private key (empty = ephemeral)
	NoRandomize bool   // if true, use default Go SSH banner
}

// NewSession creates a Session with an ephemeral ed25519 key (or user key)
// and a randomized client version string.
func NewSession(opts Options) (*Session, error) {
	var authMethods []ssh.AuthMethod

	if opts.KeyFile != "" {
		keyBytes, err := os.ReadFile(opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("read key: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else {
		// Ephemeral ed25519 key: not reused across sessions.
		_, priv, err := ed25519.GenerateKey(crand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral key: %w", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("signer from key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if opts.Password != "" {
		authMethods = append(authMethods, ssh.Password(opts.Password))
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = opts.Password
				}
				return answers, nil
			},
		))
	}

	clientVer := "SSH-2.0-Go"
	if !opts.NoRandomize {
		clientVer = bannerPool[mrand.IntN(len(bannerPool))]
	}

	return &Session{
		Config: &ssh.ClientConfig{
			User:            opts.User,
			Auth:            authMethods,
			HostKeyCallback: makeTOFU(),
			ClientVersion:   clientVer,
		},
		ClientVer:  clientVer,
		knownHosts: make(map[string]ssh.PublicKey),
	}, nil
}

// Connect dials through the SOCKS5 proxy and establishes an SSH connection.
func (s *Session) Connect(ctx context.Context, dialer proxy.Dialer, host string) (*ssh.Client, error) {
	var rawConn net.Conn
	var err error
	// Use context-aware dialer if available (bine's tor.Dialer implements it).
	type contextDialer interface {
		DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	}
	if cd, ok := dialer.(contextDialer); ok {
		rawConn, err = cd.DialContext(ctx, "tcp", host)
	} else {
		rawConn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		return nil, fmt.Errorf("socks5 dial %s: %w", host, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, host, s.Config)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", host, err)
	}

	log.Printf("connected to %s as %s (client: %s)", host, s.Config.User, s.ClientVer)
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// makeTOFU returns a HostKeyCallback that accepts the first key seen per
// host (trust-on-first-use) and rejects key changes within the session.
// Keys are never persisted to disk.
func makeTOFU() ssh.HostKeyCallback {
	known := make(map[string]ssh.PublicKey)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if prev, ok := known[hostname]; ok {
			if string(prev.Marshal()) != string(key.Marshal()) {
				return fmt.Errorf("HOST KEY CHANGED for %s — possible MITM attack", hostname)
			}
			return nil
		}
		known[hostname] = key
		log.Printf("host key accepted for %s (%s)", hostname, key.Type())
		return nil
	}
}
