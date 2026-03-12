package observability

import (
	"context"
	"log/slog"

	"github.com/LCGant/role-pdp/internal/audit"
	"github.com/LCGant/role-pdp/internal/store"
)

type AuditLogger struct {
	Sink   store.PolicyStore
	Remote *audit.Client
	Logger *slog.Logger
}

func (a *AuditLogger) RecordDecision(ctx context.Context, entry store.AuditLogEntry) {
	if a == nil {
		return
	}
	if a.Sink != nil {
		if err := a.Sink.LogDecision(ctx, entry); err != nil && a.Logger != nil {
			a.Logger.ErrorContext(ctx, "failed to record decision", "error", err)
		}
	}
	if a.Remote != nil {
		if err := a.Remote.Record(ctx, audit.EventFromDecision(entry)); err != nil && a.Logger != nil {
			a.Logger.ErrorContext(ctx, "failed to forward decision audit", "error", err)
		}
	}
}
