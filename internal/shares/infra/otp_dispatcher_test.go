package infra

import (
	"context"
	"errors"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/Rass0l/storage-boxes/internal/shares/app"
)

// TestSMTPOTPDispatcherDeliversCodeOutOfBand proves the email dispatcher
// puts the code in the outbound message addressed to the recipient and
// returns it nowhere else — the production out-of-band path.
func TestSMTPOTPDispatcherDeliversCodeOutOfBand(t *testing.T) {
	var gotAddr, gotFrom string
	var gotTo []string
	var gotMsg []byte
	var gotDeadline bool
	d := &SMTPOTPDispatcher{
		addr: "smtp.example.com:587", from: "no-reply@example.com", timeout: 5 * time.Second,
		send: func(ctx context.Context, addr string, _ smtp.Auth, from string, to []string, msg []byte) error {
			_, gotDeadline = ctx.Deadline()
			gotAddr, gotFrom, gotTo, gotMsg = addr, from, to, msg
			return nil
		},
	}
	exp := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	err := d.DispatchOTP(context.Background(), app.OTPMessage{
		ShareID: "shr_1", RecipientID: "rcp_1", RecipientEmail: "alice@example.com",
		Code: "428913", ExpiresAt: exp,
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !gotDeadline {
		t.Fatal("dispatch must bound the send with a deadline")
	}
	if gotAddr != "smtp.example.com:587" || gotFrom != "no-reply@example.com" {
		t.Fatalf("transport args: addr=%q from=%q", gotAddr, gotFrom)
	}
	if len(gotTo) != 1 || gotTo[0] != "alice@example.com" {
		t.Fatalf("recipient envelope: %v", gotTo)
	}
	body := string(gotMsg)
	if !strings.Contains(body, "428913") {
		t.Fatalf("message must carry the code; got:\n%s", body)
	}
	if !strings.Contains(body, "To: alice@example.com") {
		t.Fatalf("message must address the recipient; got:\n%s", body)
	}
	if !strings.Contains(body, exp.Format(time.RFC3339)) {
		t.Fatalf("message should mention expiry; got:\n%s", body)
	}
	if !strings.Contains(body, "\r\n") {
		t.Fatal("message must use CRLF line endings")
	}
}

// TestSMTPOTPDispatcherPropagatesSendFailure ensures a transport error
// surfaces (so the verify flow reports failure) rather than being
// swallowed — the service must not fall back to echoing the code.
func TestSMTPOTPDispatcherPropagatesSendFailure(t *testing.T) {
	d := &SMTPOTPDispatcher{
		addr: "smtp.example.com:587", from: "no-reply@example.com", timeout: 5 * time.Second,
		send: func(context.Context, string, smtp.Auth, string, []string, []byte) error {
			return errors.New("connection refused")
		},
	}
	if err := d.DispatchOTP(context.Background(), app.OTPMessage{RecipientEmail: "a@example.com", Code: "111111"}); err == nil {
		t.Fatal("expected dispatch error to propagate")
	}
}

// TestSMTPOTPDispatcherTimesOut proves a hung SMTP server can't stall the
// caller: the bounded context fires and DispatchOTP returns promptly with
// an error instead of blocking on the send.
func TestSMTPOTPDispatcherTimesOut(t *testing.T) {
	d := &SMTPOTPDispatcher{
		addr: "smtp.example.com:587", from: "no-reply@example.com", timeout: 20 * time.Millisecond,
		send: func(ctx context.Context, _ string, _ smtp.Auth, _ string, _ []string, _ []byte) error {
			<-ctx.Done() // a real hung server is bounded by DialContext + conn deadline
			return ctx.Err()
		},
	}
	start := time.Now()
	err := d.DispatchOTP(context.Background(), app.OTPMessage{RecipientEmail: "a@example.com", Code: "111111"})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("dispatch did not respect its timeout; took %s", elapsed)
	}
}

// TestSMTPOTPDispatcherRejectsEmptyInputs guards against composing a
// message with no recipient or no code.
func TestSMTPOTPDispatcherRejectsEmptyInputs(t *testing.T) {
	d := NewSMTPOTPDispatcher("smtp.example.com:587", "no-reply@example.com", "", "")
	if err := d.DispatchOTP(context.Background(), app.OTPMessage{Code: "111111"}); err == nil {
		t.Fatal("expected error for empty recipient")
	}
	if err := d.DispatchOTP(context.Background(), app.OTPMessage{RecipientEmail: "a@example.com"}); err == nil {
		t.Fatal("expected error for empty code")
	}
}

// TestNewSMTPOTPDispatcherDefaults checks the constructor sets a bounded
// timeout and configures PLAIN auth only when a username is provided.
func TestNewSMTPOTPDispatcherDefaults(t *testing.T) {
	d := NewSMTPOTPDispatcher("smtp.example.com:587", "f@example.com", "", "")
	if d.timeout <= 0 {
		t.Fatal("dispatcher must default to a positive send timeout")
	}
	if d.auth != nil {
		t.Fatal("no auth expected without a username")
	}
	if withAuth := NewSMTPOTPDispatcher("smtp.example.com:587", "f@example.com", "user", "pass"); withAuth.auth == nil {
		t.Fatal("auth expected when username provided")
	}
}
