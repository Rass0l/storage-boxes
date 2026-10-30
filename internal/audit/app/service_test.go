package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/Rass0l/storage-boxes/internal/audit/app"
	"github.com/Rass0l/storage-boxes/internal/audit/domain"
	"github.com/Rass0l/storage-boxes/internal/audit/infra"
)

func TestAuditQueryZeroValue(t *testing.T) {
	var q app.AuditQuery
	if q.SubjectID != "" {
		t.Fatal("expected zero value")
	}
}

// TestRecordAndList covers the happy path: Record writes to the repo,
// enqueues an outbox row, and List returns it with newest-first order.
func TestRecordAndList(t *testing.T) {
	ctx := context.Background()
	repo := infra.NewMemoryAuditRepository()
	outbox := infra.NewMemoryOutbox()
	svc := app.NewService(app.Deps{Repo: repo, Outbox: outbox})

	must := func(eventType, subjectID string) {
		if err := svc.Record(ctx, domain.AuditEvent{
			EventType:   eventType,
			SubjectType: domain.SubjectTypeShare,
			SubjectID:   subjectID,
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	must(domain.EventShareCreated, "shr_1")
	time.Sleep(time.Millisecond)
	must(domain.EventShareAccessed, "shr_1")

	events, err := svc.List(ctx, app.AuditQuery{SubjectID: "shr_1"})
	if err != nil || len(events) != 2 {
		t.Fatalf("list: %d %v", len(events), err)
	}
	if !events[0].OccurredAt.After(events[1].OccurredAt) {
		t.Fatalf("expected newest-first ordering")
	}

	// Outbox should have two pending rows.
	claimed, err := outbox.Claim(ctx, time.Now().UTC(), 10)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("claim: %d %v", len(claimed), err)
	}
}

// TestRecordRejectsEmptyEventType proves the service guards the required
// fields so the append-only table never receives a malformed row.
func TestRecordRejectsEmptyEventType(t *testing.T) {
	svc := app.NewService(app.Deps{Repo: infra.NewMemoryAuditRepository()})
	if err := svc.Record(context.Background(), domain.AuditEvent{}); err == nil {
		t.Fatal("expected error on empty event_type")
	}
}

// TestRiskSignalRecorded verifies the optional signal path — elevated
// severity rows carry SubjectType + SubjectID so an operator can pivot
// from a share to its flagged accesses.
func TestRiskSignalRecorded(t *testing.T) {
	ctx := context.Background()
	signals := infra.NewMemoryRiskSignals()
	svc := app.NewService(app.Deps{Repo: infra.NewMemoryAuditRepository(), Signals: signals})

	if err := svc.RecordSignal(ctx, domain.RiskSignal{
		SignalType:  "share.elevated_risk_access",
		Severity:    domain.SeverityElevated,
		SubjectType: domain.SubjectTypeShare,
		SubjectID:   "shr_hot",
		Metadata:    map[string]any{"score": 55},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := signals.ListBySubject(ctx, domain.SubjectTypeShare, "shr_hot")
	if err != nil || len(got) != 1 {
		t.Fatalf("signals: %d %v", len(got), err)
	}
	if got[0].Severity != domain.SeverityElevated {
		t.Fatalf("want elevated, got %s", got[0].Severity)
	}
}
