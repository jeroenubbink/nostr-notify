package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// NIP-17/59 event kinds.
const (
	kindDMRumor  = 14   // unsigned DM content (NIP-17)
	kindSeal     = 13   // NIP-59 seal
	kindGiftWrap = 1059 // NIP-59 gift wrap
)

// maxRelayContentBytes is the de-facto hard limit on a Nostr event's content
// field.  NIP-01 does not specify one, but 64 KiB is the common convention and
// strfry (and most other relays) reject larger events with "content is too
// large".  It is 65535, not 65536, because relays commonly track the length in
// an unsigned 16-bit field.
const maxRelayContentBytes = 65535

// errContentTooLarge is returned by buildGiftWrap when a plaintext exceeds
// NIP-44's 65535-byte plaintext cap.  BuildGiftWrap treats it as a signal to
// truncate rather than as a hard failure.
var errContentTooLarge = errors.New("content too large for NIP-44 encryption")

// BuildGiftWrap constructs a NIP-17 DM gift wrap ready for publishing.
//
// Flow: kind:14 rumor (unsigned) → kind:13 seal (NIP-44 encrypted, signed by
// senderSK) → kind:1059 gift wrap (NIP-44 encrypted, signed by a fresh
// ephemeral key).  Both seal and wrap get a random created_at up to 2 days in
// the past per NIP-59.
//
// The published event's content field is guaranteed to fit within
// maxRelayContentBytes.  NIP-44 encrypts the content twice (rumor → seal →
// wrap) and each layer adds base64 expansion plus fixed overhead, so a plaintext
// that is under the limit on its own can exceed it once gift-wrapped.  Oversized
// content is truncated on a UTF-8 boundary (with a visible marker) and rebuilt
// until the wrap fits.
func BuildGiftWrap(content, subject, senderSK, recipientPubHex string) (*nostr.Event, error) {
	// Strip invalid UTF-8 and null bytes; cron output on OpenBSD/C locale may
	// contain raw bytes, and embedded nulls break JSON/relay parsing.
	content = strings.ToValidUTF8(content, "")
	content = strings.ReplaceAll(content, "\x00", "")

	wrap, err := buildGiftWrap(content, subject, senderSK, recipientPubHex)
	switch {
	case err != nil && !errors.Is(err, errContentTooLarge):
		return nil, err
	case err == nil && len(wrap.Content) <= maxRelayContentBytes:
		return wrap, nil
	}
	// Either the wrap exceeded the relay limit or the content was too large for
	// NIP-44 to even encrypt — both are fixed by truncating.

	// Oversized.  Find the longest UTF-8-safe prefix whose wrap (plus a
	// truncation marker) still fits.  The NIP-44 ciphertext length is
	// deterministic, so the fit predicate is monotonic and binary search works.
	const marker = "\n[... truncated to fit relay limit]"

	// Byte offsets of every rune boundary (plus the end of the string), so the
	// search can truncate without splitting a multi-byte rune.
	offsets := []int{0}
	for i := 1; i <= len(content); i++ {
		if i == len(content) || utf8.RuneStart(content[i]) {
			offsets = append(offsets, i)
		}
	}

	lo, hi := 0, len(offsets)-1
	best := 0
	for lo <= hi {
		mid := (lo + hi) / 2
		w, err := buildGiftWrap(content[:offsets[mid]]+marker, subject, senderSK, recipientPubHex)
		if err != nil {
			if errors.Is(err, errContentTooLarge) {
				hi = mid - 1
				continue
			}
			return nil, err
		}
		if len(w.Content) <= maxRelayContentBytes {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}

	wrap, err = buildGiftWrap(content[:offsets[best]]+marker, subject, senderSK, recipientPubHex)
	if err != nil {
		return nil, err
	}
	slog.Warn("content truncated to fit relay limit",
		"original_bytes", len(content),
		"sent_bytes", offsets[best]+len(marker),
		"wrap_bytes", len(wrap.Content),
	)
	return wrap, nil
}

// buildGiftWrap performs the actual NIP-17/59 construction.  It is the core of
// BuildGiftWrap, split out so the fit-trimming logic can rebuild with shorter
// content without repeating the sanitisation steps.
func buildGiftWrap(content, subject, senderSK, recipientPubHex string) (*nostr.Event, error) {
	senderPubHex, err := nostr.GetPublicKey(senderSK)
	if err != nil {
		return nil, fmt.Errorf("derive sender pubkey: %w", err)
	}

	rumor := nostr.Event{
		Kind:      kindDMRumor,
		Content:   content,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		PubKey:    senderPubHex,
		Tags: nostr.Tags{
			{"p", recipientPubHex},
			{"subject", subject},
		},
	}
	rumor.ID = rumor.GetID()
	// Rumor is intentionally left unsigned.

	rumorJSON, err := json.Marshal(rumor)
	if err != nil {
		return nil, fmt.Errorf("marshal rumor: %w", err)
	}
	if len(rumorJSON) > nip44.MaxPlaintextSize {
		return nil, errContentTooLarge
	}

	convKey1, err := nip44.GenerateConversationKey(recipientPubHex, senderSK)
	if err != nil {
		return nil, fmt.Errorf("seal conv key: %w", err)
	}
	sealContent, err := nip44.Encrypt(string(rumorJSON), convKey1)
	if err != nil {
		return nil, fmt.Errorf("seal encrypt: %w", err)
	}

	seal := nostr.Event{
		Kind:      kindSeal,
		Content:   sealContent,
		CreatedAt: randomPastTimestamp(2 * 24 * time.Hour),
		PubKey:    senderPubHex,
		Tags:      nostr.Tags{},
	}
	if err = seal.Sign(senderSK); err != nil {
		return nil, fmt.Errorf("seal sign: %w", err)
	}

	sealJSON, err := json.Marshal(seal)
	if err != nil {
		return nil, fmt.Errorf("marshal seal: %w", err)
	}
	if len(sealJSON) > nip44.MaxPlaintextSize {
		return nil, errContentTooLarge
	}

	ephemeralSK := nostr.GeneratePrivateKey()
	ephemeralPubHex, err := nostr.GetPublicKey(ephemeralSK)
	if err != nil {
		return nil, fmt.Errorf("derive ephemeral pubkey: %w", err)
	}

	convKey2, err := nip44.GenerateConversationKey(recipientPubHex, ephemeralSK)
	if err != nil {
		return nil, fmt.Errorf("wrap conv key: %w", err)
	}
	wrapContent, err := nip44.Encrypt(string(sealJSON), convKey2)
	if err != nil {
		return nil, fmt.Errorf("wrap encrypt: %w", err)
	}

	giftWrap := nostr.Event{
		Kind:      kindGiftWrap,
		Content:   wrapContent,
		CreatedAt: randomPastTimestamp(2 * 24 * time.Hour),
		PubKey:    ephemeralPubHex,
		Tags: nostr.Tags{
			{"p", recipientPubHex},
		},
	}
	if err = giftWrap.Sign(ephemeralSK); err != nil {
		return nil, fmt.Errorf("gift wrap sign: %w", err)
	}

	return &giftWrap, nil
}

func randomPastTimestamp(maxAge time.Duration) nostr.Timestamp {
	offset := time.Duration(rand.Int64N(int64(maxAge)))
	return nostr.Timestamp(time.Now().Add(-offset).Unix())
}
