package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// NIP-17/59 event kinds.
const (
	kindDMRumor  = 14   // unsigned DM content (NIP-17)
	kindSeal     = 13   // NIP-59 seal
	kindGiftWrap = 1059 // NIP-59 gift wrap
)

// BuildGiftWrap constructs a NIP-17 DM gift wrap ready for publishing.
//
// Flow: kind:14 rumor (unsigned) → kind:13 seal (NIP-44 encrypted, signed by
// senderSK) → kind:1059 gift wrap (NIP-44 encrypted, signed by a fresh
// ephemeral key).  Both seal and wrap get a random created_at up to 2 days in
// the past per NIP-59.
func BuildGiftWrap(content, subject, senderSK, recipientPubHex string) (*nostr.Event, error) {
	// Strip invalid UTF-8 and null bytes; cron output on OpenBSD/C locale may
	// contain raw bytes, and embedded nulls break JSON/relay parsing.
	content = strings.ToValidUTF8(content, "")
	content = strings.ReplaceAll(content, "\x00", "")

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
