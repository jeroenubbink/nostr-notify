package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config holds the parsed contents of a config.toml file.
// Only the fields used in Phase 1 are present; see SPEC.md §7 for the full
// schema that will be added in later phases.
//
// TODO (Phase 2): add [delivery] retry_attempts, retry_delay_seconds, spool_dir.
//   For multi-user machines, spool_dir should be per-user
//   (~/.local/share/nostr-notify/spool) rather than a shared /var/spool path to
//   avoid permission conflicts between different operator accounts.
// TODO (Phase 2): add [logging] log_file, log_level.
type Config struct {
	Identity  IdentityConfig  `toml:"identity"`
	Recipient RecipientConfig `toml:"recipient"`
	Relays    RelaysConfig    `toml:"relays"`
}

type IdentityConfig struct {
	KeyFile string `toml:"key_file"`
}

type RecipientConfig struct {
	// Pubkey is the recipient's npub1... address (bech32).
	// Hex format is also accepted for compatibility.
	Pubkey string `toml:"pubkey"`
}

type RelaysConfig struct {
	URLs []string `toml:"urls"`
}

// configPaths returns the candidate config file locations in preference order:
// user config (~/.config/nostr-notify/config.toml) before system config.
func configPaths() []string {
	paths := []string{"/etc/nostr-notify/config.toml"}
	if home, err := os.UserHomeDir(); err == nil {
		// Prepend so user config takes precedence.
		paths = append([]string{filepath.Join(home, ".config", "nostr-notify", "config.toml")}, paths...)
	}
	return paths
}

// loadConfig searches the standard config file locations and returns the parsed
// Config.  If no config file is found, an empty Config is returned (caller
// falls back to defaults).  A file that exists but is malformed is a hard
// error.
func loadConfig() (*Config, error) {
	for _, p := range configPaths() {
		if _, err := os.Stat(p); err != nil {
			continue // not found, try next
		}
		var cfg Config
		if _, err := toml.DecodeFile(p, &cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", p, err)
		}
		return &cfg, nil
	}
	return &Config{}, nil
}
