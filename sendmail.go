package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"strings"
	"time"
)

// runSendmail implements the "nostr-notify sendmail" subcommand.
//
// It reads a raw RFC 2822 email from stdin, extracts the Subject header and
// plain-text body, and publishes a NIP-17 DM using the standard config.
//
// All arguments are accepted and ignored for sendmail compatibility; cron and
// most daemons call sendmail with flags like -oi, -t, or a recipient address
// that we do not need.  The only exception is --debug, which enables verbose
// logging to stderr.
func runSendmail(args []string) int {
	debug := false
	for _, a := range args {
		if a == "--debug" || a == "-debug" {
			debug = true
		}
	}
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	msg, err := mail.ReadMessage(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify sendmail: parse email: %v\n", err)
		return 1
	}

	subject := decodeMailHeader(msg.Header.Get("Subject"))
	if subject == "" {
		host, _ := os.Hostname()
		subject = fmt.Sprintf("mail to root — %s %s", host, time.Now().Format("2006-01-02"))
	}

	const bodyLimit = 64 * 1024
	content := extractMailBody(msg, bodyLimit)
	if content == "" {
		fmt.Fprintf(os.Stderr, "nostr-notify sendmail: empty message body, nothing to send\n")
		return 1
	}

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify sendmail: %v\n", err)
		return 1
	}
	params, err := resolveParams(cfg, cliOverrides{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify sendmail: %v\n", err)
		return 1
	}

	giftWrap, err := BuildGiftWrap(content, subject, params.serviceSK, params.recipientPubHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nostr-notify sendmail: build gift wrap: %v\n", err)
		return 1
	}
	slog.Debug("gift wrap built", "id", giftWrap.ID[:8])

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, anySuccess := PublishToRelays(ctx, giftWrap, params.relays, params.serviceSK)
	if !anySuccess {
		fmt.Fprintf(os.Stderr, "nostr-notify sendmail: all relays failed\n")
		return 1
	}

	return 0
}

// decodeMailHeader decodes an RFC 2047 encoded header value (e.g.
// =?UTF-8?Q?subject_text?=) into a plain UTF-8 string.
func decodeMailHeader(s string) string {
	if s == "" {
		return ""
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(s)
	if err != nil {
		return s // fall back to raw value
	}
	return decoded
}

// extractMailBody returns the plain-text body of a parsed email, applying the
// given byte limit.  It handles the most common email structures produced by
// cron daemons and system utilities.
func extractMailBody(msg *mail.Message, limit int) string {
	ct := msg.Header.Get("Content-Type")
	cte := msg.Header.Get("Content-Transfer-Encoding")

	if ct == "" {
		// No Content-Type — treat as plain text.
		return readTextBody(msg.Body, cte, limit)
	}

	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return readTextBody(msg.Body, cte, limit)
	}

	switch {
	case strings.HasPrefix(mediaType, "text/plain"):
		return readTextBody(msg.Body, cte, limit)
	case strings.HasPrefix(mediaType, "multipart/"):
		return extractMultipartText(msg.Body, params["boundary"], limit)
	default:
		return fmt.Sprintf("[non-text email — Content-Type: %s]", mediaType)
	}
}

// readTextBody decodes a text body according to its Content-Transfer-Encoding,
// applies the byte limit, and sanitises the result for Nostr.
func readTextBody(r io.Reader, cte string, limit int) string {
	var decoded io.Reader
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "quoted-printable":
		decoded = quotedprintable.NewReader(r)
	case "base64":
		decoded = base64.NewDecoder(base64.StdEncoding, &crlfStripper{r: r})
	default:
		decoded = r
	}

	data, _ := io.ReadAll(io.LimitReader(decoded, int64(limit)+1))

	truncated := len(data) > limit
	if truncated {
		data = data[:limit]
	}

	content := strings.ToValidUTF8(string(data), "")
	content = strings.ReplaceAll(content, "\x00", "")
	content = strings.TrimRight(content, "\n")
	if truncated {
		content += "\n[... truncated]"
		slog.Warn("sendmail body truncated", "limit_bytes", limit)
	}
	return content
}

// extractMultipartText walks a MIME multipart message and returns the first
// text/plain part found.
func extractMultipartText(r io.Reader, boundary string, limit int) string {
	mr := multipart.NewReader(r, boundary)
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		partCT := part.Header.Get("Content-Type")
		if partCT == "" {
			return readTextBody(part, part.Header.Get("Content-Transfer-Encoding"), limit)
		}
		mediaType, _, err := mime.ParseMediaType(partCT)
		if err != nil {
			continue
		}
		if strings.HasPrefix(mediaType, "text/plain") {
			return readTextBody(part, part.Header.Get("Content-Transfer-Encoding"), limit)
		}
	}
	return "[no text/plain part found in multipart email]"
}

// crlfStripper strips CR and LF bytes from the underlying reader so that
// base64.NewDecoder can handle line-wrapped email base64 content.
type crlfStripper struct{ r io.Reader }

func (c *crlfStripper) Read(p []byte) (int, error) {
	tmp := make([]byte, len(p))
	n, err := c.r.Read(tmp)
	j := 0
	for i := 0; i < n; i++ {
		if tmp[i] != '\r' && tmp[i] != '\n' {
			p[j] = tmp[i]
			j++
		}
	}
	return j, err
}
