// Command anonssh is an anonymous SSH client that routes through Tor and
// avoids fingerprint reuse across sessions.
//
// Usage:
//
//	anonssh [flags] user@host [-p port] [-- command...]
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"anonssh/internal/exit"
	"anonssh/internal/sshcli"
	"anonssh/internal/torembed"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"golang.org/x/term"
)

var version = "dev"

func main() {
	log.SetFlags(0)
	log.SetPrefix("anonssh: ")

	port := flag.Int("p", 22, "SSH port")
	keyFile := flag.String("key", "", "path to private key (default: ephemeral ed25519)")
	password := flag.String("password", "", "password for auth fallback")
	noRandomize := flag.Bool("no-randomize", false, "disable SSH banner randomization")
	torSocks := flag.String("tor-socks", "", "external Tor SOCKS5 proxy (host:port); if empty, use embedded tor")
	stateDir := flag.String("state-dir", "", "persist tor state directory across runs")
	newIdentity := flag.Bool("new-identity", false, "force new tor circuit")
	verbose := flag.Bool("v", false, "verbose logging")
	showVersion := flag.Bool("V", false, "print version and exit")
	cmdFlag := flag.String("cmd", "", "execute a single command instead of shell")
	var exitCountries []string
	flag.Func("exit-country", "exit node country code (repeatable)", func(s string) error {
		exitCountries = append(exitCountries, s)
		return nil
	})

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] user@host [-- command...]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Anonymous SSH client. Routes through Tor with ephemeral identities.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("anonssh %s\n", version)
		os.Exit(0)
	}

	if *verbose {
		log.SetOutput(os.Stderr)
	} else {
		log.SetOutput(io.Discard)
	}

	// Parse user@host.
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(1)
	}
	user, host := parseUserHost(args[0])
	if user == "" || host == "" {
		log.Fatal("specify user@host")
	}
	target := net.JoinHostPort(host, strconv.Itoa(*port))
	execCmd := *cmdFlag

	// Context with signal handling.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── Tor ──
	var dialer proxy.Dialer
	var torRunner *torembed.Runner
	debugWriter := io.Discard
	if *verbose {
		debugWriter = os.Stderr
	}

	if *torSocks != "" {
		addr := strings.TrimPrefix(*torSocks, "socks5://")
		if !strings.Contains(addr, ":") {
			addr += ":1080"
		}
		var err error
		dialer, err = proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
		if err != nil {
			log.Fatalf("socks5: %v", err)
		}
		log.Printf("using external SOCKS5 at %s", addr)
	} else {
		log.Printf("starting embedded tor...")
		var sd *string
		if *stateDir != "" {
			sd = stateDir
		}
		var err error
		torRunner, err = torembed.Start(ctx, debugWriter, true, sd, nil)
		if err != nil {
			log.Fatalf("tor start: %v", err)
		}
		defer torRunner.Close()

		if *newIdentity {
			if err := torRunner.ExitSignal(); err != nil {
				log.Printf("warning: NEWNYM failed: %v", err)
			}
		}

		td, err := torRunner.Dialer(ctx)
		if err != nil {
			log.Fatalf("tor dialer: %v", err)
		}
		dialer = td
	}

	// ── Exit selection ──
	if len(exitCountries) > 0 {
		sel := exit.New()
		relay, err := sel.Pick(ctx, *port, exitCountries)
		if err != nil {
			log.Printf("exit selection: %v (using default)", err)
		} else {
			log.Printf("selected exit: %s (%s, %s)", relay.Nickname, relay.Country, relay.CountryName)
		}
		// TODO: set ExitNodes via torRunner.SetConf when fingerprint is available.
	}

	// ── SSH session ──
	sess, err := sshcli.NewSession(sshcli.Options{
		User:        user,
		Password:    *password,
		KeyFile:     *keyFile,
		NoRandomize: *noRandomize,
	})
	if err != nil {
		log.Fatalf("ssh session: %v", err)
	}

	client, err := sess.Connect(ctx, dialer, target)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer client.Close()

	if execCmd != "" {
		// Single command mode.
		session, err := client.NewSession()
		if err != nil {
			log.Fatalf("new session: %v", err)
		}
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		session.Stdin = os.Stdin
		if err := session.Run(execCmd); err != nil {
			log.Fatalf("run: %v", err)
		}
		return
	}

	// Interactive shell mode.
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("new session: %v", err)
	}
	defer session.Close()

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// Request a PTY for interactive use.
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		w, h = 80, 24
	}
	if err := session.RequestPty("xterm-256color", h, w, modes); err != nil {
		log.Fatalf("pty: %v", err)
	}

	if err := session.Shell(); err != nil {
		log.Fatalf("shell: %v", err)
	}
	session.Wait()
}

func parseUserHost(s string) (string, string) {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}
