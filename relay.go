package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// PublishResult holds the outcome of a single relay publish attempt.
type PublishResult struct {
	URL     string
	Success bool
	Message string
	Err     error
}

// PublishToRelays attempts to publish event to every relay URL.  NIP-42 AUTH
// is handled transparently via WithAuthHandler.  Returns the per-relay results
// and whether at least one relay accepted the event.
func PublishToRelays(ctx context.Context, event *nostr.Event, relayURLs []string, serviceSK string) ([]PublishResult, bool) {
	results := make([]PublishResult, len(relayURLs))
	var wg sync.WaitGroup
	for i, url := range relayURLs {
		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			results[i] = publishOne(ctx, event, url, serviceSK)
		}(i, url)
	}
	wg.Wait()

	anySuccess := false
	for _, res := range results {
		if res.Success {
			anySuccess = true
			slog.Info("relay accepted", "url", res.URL, "id", event.ID[:8])
		} else if res.Err != nil {
			slog.Warn("relay error", "url", res.URL, "err", res.Err)
		} else {
			slog.Warn("relay rejected", "url", res.URL, "msg", res.Message)
		}
	}

	return results, anySuccess
}

func publishOne(ctx context.Context, event *nostr.Event, url, serviceSK string) PublishResult {
	relay, err := nostr.RelayConnect(ctx, url)
	if err != nil {
		return PublishResult{URL: url, Err: fmt.Errorf("connect: %w", err)}
	}
	defer relay.Close()

	doAuth := func() error {
		return relay.Auth(ctx, func(evt *nostr.Event) error {
			return evt.Sign(serviceSK)
		})
	}

	// Some relays (including Haven) send the AUTH challenge immediately on
	// connect.  Give the async read loop a moment to receive it, then try a
	// proactive AUTH before the first publish attempt.
	time.Sleep(200 * time.Millisecond)
	if err = doAuth(); err != nil {
		// Not fatal yet — relay may not have sent a challenge, or doesn't
		// require AUTH at all.  Surface it for visibility.
		slog.Debug("proactive AUTH result", "url", url, "err", err)
	}

	if err = relay.Publish(ctx, *event); err != nil {
		if !strings.Contains(err.Error(), "auth-required") {
			return PublishResult{URL: url, Message: err.Error(), Err: err}
		}

		// Relay replied "auth-required:" — it sent a fresh challenge as part
		// of that response.  The challenge is now stored in relay.challenge;
		// authenticate and retry exactly once.
		slog.Debug("auth-required on publish, retrying with fresh challenge", "url", url)
		if authErr := doAuth(); authErr != nil {
			return PublishResult{URL: url, Err: fmt.Errorf("auth rejected by relay: %w (is the service npub whitelisted?)", authErr)}
		}
		if err = relay.Publish(ctx, *event); err != nil {
			return PublishResult{URL: url, Message: err.Error(), Err: err}
		}
	}

	return PublishResult{URL: url, Success: true}
}
