package infra

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
)

// defaultOTPDispatchTimeout bounds the whole SMTP exchange (dial + every
// read/write). Like the database path, the mail path must not block a
// request indefinitely on an unreachable or slow server — a stalled send
// would otherwise pin a gateway goroutine and hang the recipient's verify
// request. Tunable per-dispatcher via the timeout field.
const defaultOTPDispatchTimeout = 15 * time.Second

// SMTPOTPDispatcher delivers restricted-share one-time codes to recipients
// over email — a channel separate from the HTTP response the recipient
// used to submit their passcode. It is the shippable production
// implementation of app.OTPDispatcher: wiring it (via SHARE_OTP_SMTP_*
// config) makes require_otp shares usable in a production-like
// deployment, where the code must never be returned in a response or
// written to a log.
//
// The code is placed only in the outbound message body. The dispatcher
// never logs it and never returns it to the caller; a send failure (bad
// address, auth rejection, timeout) surfaces as an error so the verify
// flow reports a generic failure and the recipient retries — the service
// never falls back to echoing.
type SMTPOTPDispatcher struct {
	addr    string
	from    string
	auth    smtp.Auth
	timeout time.Duration
	// send is the transport seam. Defaults to a context-bounded SMTP
	// client; tests inject a capturing stub so message composition and
	// timeout behavior can be asserted without a live SMTP server.
	send func(ctx context.Context, addr string, a smtp.Auth, from string, to []string, msg []byte) error
}

var _ app.OTPDispatcher = (*SMTPOTPDispatcher)(nil)

// NewSMTPOTPDispatcher builds an email OTP dispatcher. addr is host:port;
// from is the envelope/header sender. When username is non-empty, PLAIN
// auth is used (the SMTP server is expected to offer STARTTLS — net/smtp
// refuses PLAIN auth over an unencrypted, non-localhost connection).
func NewSMTPOTPDispatcher(addr, from, username, password string) *SMTPOTPDispatcher {
	var auth smtp.Auth
	if username != "" {
		host := addr
		if i := strings.LastIndex(addr, ":"); i > 0 {
			host = addr[:i]
		}
		auth = smtp.PlainAuth("", username, password, host)
	}
	return &SMTPOTPDispatcher{addr: addr, from: from, auth: auth, timeout: defaultOTPDispatchTimeout, send: sendMail}
}

func (d *SMTPOTPDispatcher) DispatchOTP(ctx context.Context, msg app.OTPMessage) error {
	if msg.RecipientEmail == "" {
		return fmt.Errorf("otp dispatch: empty recipient")
	}
	if msg.Code == "" {
		return fmt.Errorf("otp dispatch: empty code")
	}
	// Bound the whole exchange. The default transport honors this via
	// DialContext + a connection deadline; the timeout also caps the
	// time a verify request can wait on mail delivery.
	if d.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}
	return d.send(ctx, d.addr, d.auth, d.from, []string{msg.RecipientEmail}, buildOTPEmail(d.from, msg))
}

// sendMail is the production transport. Unlike smtp.SendMail it dials with
// a context (so a dead server fails fast) and sets a connection deadline
// (so a half-open or slow server can't stall mid-protocol). STARTTLS is
// used when offered; auth only when configured.
func sendMail(ctx context.Context, addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("otp dispatch: bad smtp addr %q: %w", addr, err)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("otp dispatch: dial: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("otp dispatch: smtp client: %w", err)
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return fmt.Errorf("otp dispatch: starttls: %w", err)
		}
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("otp dispatch: auth: %w", err)
			}
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("otp dispatch: mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("otp dispatch: rcpt: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("otp dispatch: data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("otp dispatch: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("otp dispatch: close: %w", err)
	}
	return c.Quit()
}

// buildOTPEmail composes the RFC 5322 message. CRLF line endings are
// required by SMTP. The code lives in the body only.
func buildOTPEmail(from string, msg app.OTPMessage) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + msg.RecipientEmail + "\r\n")
	b.WriteString("Subject: Your one-time access code\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString("Your one-time access code is: " + msg.Code + "\r\n")
	if !msg.ExpiresAt.IsZero() {
		b.WriteString("It expires at " + msg.ExpiresAt.UTC().Format(time.RFC3339) + ".\r\n")
	}
	b.WriteString("\r\nEnter it on the verification page to finish downloading the shared file.\r\n")
	b.WriteString("If you did not request this, you can ignore this message.\r\n")
	return []byte(b.String())
}
