package main

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// testKeys returns a fresh sender and recipient keypair for test use.
func testKeys(t *testing.T) (senderSK, recipientSK, recipientPub string) {
	t.Helper()
	senderSK = nostr.GeneratePrivateKey()
	recipientSK = nostr.GeneratePrivateKey()
	var err error
	recipientPub, err = nostr.GetPublicKey(recipientSK)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// decryptRumor decrypts a gift wrap back to its kind:14 rumor content using the
// recipient's private key, mirroring what a NIP-17 client does.
func decryptRumor(t *testing.T, wrap *nostr.Event, recipientSK string) string {
	t.Helper()

	convWrap, err := nip44.GenerateConversationKey(wrap.PubKey, recipientSK)
	if err != nil {
		t.Fatalf("wrap conv key: %v", err)
	}
	sealJSON, err := nip44.Decrypt(wrap.Content, convWrap)
	if err != nil {
		t.Fatalf("decrypt wrap: %v", err)
	}
	var seal nostr.Event
	if err := json.Unmarshal([]byte(sealJSON), &seal); err != nil {
		t.Fatalf("unmarshal seal: %v", err)
	}

	convSeal, err := nip44.GenerateConversationKey(seal.PubKey, recipientSK)
	if err != nil {
		t.Fatalf("seal conv key: %v", err)
	}
	rumorJSON, err := nip44.Decrypt(seal.Content, convSeal)
	if err != nil {
		t.Fatalf("decrypt seal: %v", err)
	}
	var rumor nostr.Event
	if err := json.Unmarshal([]byte(rumorJSON), &rumor); err != nil {
		t.Fatalf("unmarshal rumor: %v", err)
	}
	return rumor.Content
}

func TestBuildGiftWrapFitsRelayLimit(t *testing.T) {
	senderSK, recipientSK, recipientPub := testKeys(t)
	// ~76 KB of multibyte text — far more than survives double NIP-44 encryption.
	content := strings.Repeat("héllo wörld 👋\n", 4000)
	wrap, err := BuildGiftWrap(content, "subject", senderSK, recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrap.Content) > maxRelayContentBytes {
		t.Fatalf("wrap content %d bytes exceeds relay limit %d", len(wrap.Content), maxRelayContentBytes)
	}

	const marker = "\n[... truncated to fit relay limit]"
	got := decryptRumor(t, wrap, recipientSK)
	if !strings.HasSuffix(got, marker) {
		t.Fatalf("truncated message missing marker; tail: %q", got[len(got)-64:])
	}
	prefix := strings.TrimSuffix(got, marker)
	if !strings.HasPrefix(content, prefix) {
		t.Fatal("truncated message is not a prefix of the original content")
	}
	if !utf8.ValidString(prefix) {
		t.Fatal("truncated message is not valid UTF-8 (a rune was split)")
	}
}

func TestBuildGiftWrapRoundTripsSmallContent(t *testing.T) {
	senderSK, recipientSK, recipientPub := testKeys(t)
	content := "hello, this is a small message"
	wrap, err := BuildGiftWrap(content, "subject", senderSK, recipientPub)
	if err != nil {
		t.Fatal(err)
	}
	got := decryptRumor(t, wrap, recipientSK)
	if got != content {
		t.Fatalf("round trip mismatch: got %q want %q", got, content)
	}
}
