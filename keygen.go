package main

import (
	"fmt"
	"os"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func runKeygen(keyFilePath string) int {
	if _, err := os.Stat(keyFilePath); err == nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: key file already exists: %s\n", keyFilePath)
		fmt.Fprintf(os.Stderr, "nostr-notify: remove it first if you want to generate a new keypair\n")
		return 1
	}

	skHex := nostr.GeneratePrivateKey()
	pkHex, err := nostr.GetPublicKey(skHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: derive pubkey: %v\n", err)
		return 1
	}

	nsec, err := nip19.EncodePrivateKey(skHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: encode nsec: %v\n", err)
		return 1
	}
	npub, err := nip19.EncodePublicKey(pkHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: encode npub: %v\n", err)
		return 1
	}

	content := fmt.Sprintf("# npub: %s\n%s\n", npub, nsec)
	if err = os.WriteFile(keyFilePath, []byte(content), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify: write key file: %v\n", err)
		return 1
	}

	// Machine-readable output: just the npub on stdout.
	fmt.Println(npub)

	// Human-readable guidance on stderr.
	fmt.Fprintf(os.Stderr, "keypair written to %s\n", keyFilePath)
	fmt.Fprintf(os.Stderr, "add this npub to your Haven whitelist so the service key can publish:\n")
	fmt.Fprintf(os.Stderr, "  %s\n", npub)

	return 0
}
