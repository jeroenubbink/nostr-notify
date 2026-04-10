package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr/nip19"
)

// Set at build time via -ldflags "-X main.version=..."
var version = "dev"

const (
	// defaultKeyFile is the fallback key path when no config file and no flag
	// specifies one.  Convenient for development; production installs use the
	// config file to set identity.key_file = /etc/nostr-notify/service.nsec.
	defaultKeyFile = "./service.nsec"

)

// defaultRelayURLs is the last-resort relay list used when the config file has
// no [relays] section and --relays is not given.  NIP-59 gift-wrapped events
// (kind:1059) are safe to publish to public relays — the content is
// end-to-end encrypted and relays see only a blob addressed to a pubkey.
var defaultRelayURLs = []string{
	"wss://relay.damus.io",
	"wss://relay.nostr.band",
	"wss://nostr.mom",
	"wss://relay.primal.net",
	"wss://relay.snort.social",
}

func main() {
	// Dispatch subcommands before the main flag set is parsed.
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		// Resolve default key file path: config file > hardcoded default.
		keyDefault := defaultKeyFile
		if cfg, err := loadConfig(); err == nil && cfg.Identity.KeyFile != "" {
			keyDefault = cfg.Identity.KeyFile
		}
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		keyFile := fs.String("key-file", keyDefault, "Path to write the generated key file")
		fs.Parse(os.Args[2:])
		os.Exit(runKeygen(*keyFile))
	}

	os.Exit(run())
}

func run() int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: %v\n", err)
		return 1
	}

	var (
		subject      = flag.String("subject", "", "Message subject (default: hostname + date)")
		to           = flag.String("to", "", "Recipient pubkey (npub or hex); overrides config")
		keyFile      = flag.String("key-file", "", "Path to service nsec file; overrides config")
		inputFile    = flag.String("file", "", "Read content from file instead of stdin")
		relayList    = flag.String("relays", "", "Comma-separated relay URLs; overrides config")
		format       = flag.String("format", "", `Content format: "plain" (default) or "code" (wrap in fenced code block)`)
		contentLimit = flag.Int("content-limit", 64*1024, "Maximum content size in bytes; excess is truncated")
		debug        = flag.Bool("debug", false, "Enable debug logging")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	// --- Service key: flag > config > default path / env var ---
	resolvedKeyFile := *keyFile
	if resolvedKeyFile == "" {
		resolvedKeyFile = cfg.Identity.KeyFile
	}
	serviceSK, err := loadServiceKey(resolvedKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: key error: %v\n", err)
		return 1
	}

	// --- Recipient pubkey: flag > config (required; no built-in default) ---
	recipientNpub := *to
	if recipientNpub == "" {
		recipientNpub = cfg.Recipient.Pubkey
	}
	if recipientNpub == "" {
		fmt.Fprintf(os.Stderr, "nostr-notify: recipient pubkey not set; add [recipient] pubkey to config or use --to\n")
		return 1
	}
	recipientPubHex, err := resolveHexPubkey(recipientNpub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: bad recipient pubkey: %v\n", err)
		return 1
	}

	// --- Relay list: flag > config > compiled-in defaults ---
	var relays []string
	switch {
	case *relayList != "":
		relays = splitTrimmed(*relayList, ",")
	case len(cfg.Relays.URLs) > 0:
		relays = cfg.Relays.URLs
	default:
		relays = defaultRelayURLs
	}

	// --- Subject ---
	subj := *subject
	if subj == "" {
		host, _ := os.Hostname()
		subj = fmt.Sprintf("%s %s", host, time.Now().Format("2006-01-02"))
	}

	// --- Format ---
	resolvedFormat := *format
	if resolvedFormat == "" {
		resolvedFormat = cfg.Message.Format
	}
	if resolvedFormat == "" {
		resolvedFormat = "plain"
	}
	if resolvedFormat != "plain" && resolvedFormat != "code" {
		fmt.Fprintf(os.Stderr, "nostr-notify: unknown format %q; use \"plain\" or \"code\"\n", resolvedFormat)
		return 1
	}

	// --- Content ---
	content, err := readContent(*inputFile, *contentLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: read input: %v\n", err)
		return 1
	}
	if content == "" {
		fmt.Fprintf(os.Stderr, "nostr-notify: empty content, nothing to send\n")
		return 1
	}
	if resolvedFormat == "code" {
		content = "```\n" + content + "```"
	}

	// --- Build NIP-17 gift wrap ---
	giftWrap, err := BuildGiftWrap(content, subj, serviceSK, recipientPubHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: build gift wrap: %v\n", err)
		return 1
	}
	slog.Debug("gift wrap built", "id", giftWrap.ID[:8], "kind", giftWrap.Kind)

	// --- Publish ---
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, anySuccess := PublishToRelays(ctx, giftWrap, relays, serviceSK)
	if !anySuccess {
		fmt.Fprintf(os.Stderr, "nostr-notify: all relays failed\n")
		return 1
	}

	return 0
}

// loadServiceKey resolves the service nsec in this order:
//  1. explicit --key-file path
//  2. defaultKeyFile (./service.nsec) if it exists
//  3. NOSTR_NSEC environment variable
func loadServiceKey(keyFilePath string) (string, error) {
	var raw string

	switch {
	case keyFilePath != "":
		nsec, err := readKeyFile(keyFilePath)
		if err != nil {
			return "", fmt.Errorf("read key file %q: %w", keyFilePath, err)
		}
		raw = nsec

	case fileExists(defaultKeyFile):
		nsec, err := readKeyFile(defaultKeyFile)
		if err != nil {
			return "", fmt.Errorf("read default key file %q: %w", defaultKeyFile, err)
		}
		raw = nsec

	case os.Getenv("NOSTR_NSEC") != "":
		raw = strings.TrimSpace(os.Getenv("NOSTR_NSEC"))

	default:
		return "", fmt.Errorf("no service key found; run 'nostr-notify keygen' to generate one")
	}

	return decodeBech32Key(raw, "nsec")
}

// readKeyFile reads a key file, skipping comment lines (starting with #),
// and returns the first non-empty content line (expected to be an nsec).
func readKeyFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line, nil
	}
	return "", fmt.Errorf("no key found in file (file may be empty or contain only comments)")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// decodeBech32Key accepts a bech32-encoded key (nsec/npub) or a 64-char hex
// string and returns the hex key.  kind is the expected bech32 prefix and is
// used only in error messages.
func decodeBech32Key(s, kind string) (string, error) {
	if strings.HasPrefix(s, kind) {
		_, decoded, err := nip19.Decode(s)
		if err != nil {
			return "", fmt.Errorf("decode %s: %w", kind, err)
		}
		key, ok := decoded.(string)
		if !ok {
			return "", fmt.Errorf("unexpected decoded type from %s", kind)
		}
		return key, nil
	}
	if len(s) == 64 && isHex(s) {
		return s, nil
	}
	return "", fmt.Errorf("unrecognised %s format (expected %s1... or 64-char hex)", kind, kind)
}

func resolveHexPubkey(s string) (string, error) { return decodeBech32Key(s, "npub") }

func readContent(filePath string, limit int) (string, error) {
	var r io.Reader
	if filePath != "" {
		f, err := os.Open(filePath)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	} else {
		r = os.Stdin
	}

	// Read up to limit+1 bytes so we can detect whether input was truncated.
	data, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return "", err
	}

	truncated := len(data) > limit
	if truncated {
		data = data[:limit]
	}

	// Strip any invalid UTF-8, including partial rune at the truncation boundary.
	content := strings.ToValidUTF8(string(data), "")
	if truncated {
		content += "\n[... output truncated]\n"
		slog.Warn("content truncated", "limit_bytes", limit)
	}

	return content, nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func splitTrimmed(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
