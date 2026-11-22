package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrApprovalUnavailable = errors.New("matching approval is unavailable")
	ErrDeploymentLocked    = errors.New("deployment scope is already locked")
	ErrDeploymentLockLost  = errors.New("deployment lock is no longer held")
)

type ApprovalRecord struct {
	ID           string
	PlanDigest   string
	Actor        string
	TargetDigest string
	ScopeDigest  string
	ExpiresAt    string
}

type OperationEvent struct {
	ID            string
	CorrelationID string
	PlanDigest    string
	Actor         string
	ResourceID    string
	EventType     string
	Status        string
	MetadataJSON  string
	OccurredAt    string
}

const maxDeploymentLockLease = 15 * time.Minute

func (s *Store) CreateApproval(ctx context.Context, approval ApprovalRecord, event OperationEvent) error {
	expiry, err := time.Parse(time.RFC3339Nano, approval.ExpiresAt)
	now := time.Now()
	if err != nil || !expiry.After(now) || expiry.After(now.Add(5*time.Minute)) {
		return errors.New("approval expiry must be in the future and at most 5 minutes")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin approval transaction: %w", err)
	}
	defer tx.Rollback()
	if err := validateEvent(event); err != nil {
		return err
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM release_plans WHERE plan_digest = ?`, approval.PlanDigest).Scan(&exists); err != nil {
		return fmt.Errorf("verify approval plan: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO approvals (
		approval_id, plan_digest, actor, target_digest, scope_digest, expires_at, created_at
	) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`, approval.ID, approval.PlanDigest, approval.Actor,
		approval.TargetDigest, approval.ScopeDigest, approval.ExpiresAt); err != nil {
		return fmt.Errorf("save plan approval: %w", err)
	}
	if err := insertOperationEvent(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit plan approval: %w", err)
	}
	return nil
}

func (s *Store) ConsumeApproval(ctx context.Context, approval ApprovalRecord, event OperationEvent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin approval consumption: %w", err)
	}
	defer tx.Rollback()
	if err := validateEvent(event); err != nil {
		return err
	}
	var id string
	err = tx.QueryRowContext(ctx, `SELECT approval_id FROM approvals
		WHERE plan_digest = ? AND actor = ? AND target_digest = ? AND scope_digest = ?
		AND consumed_at IS NULL AND julianday(expires_at) > julianday('now')
		ORDER BY created_at DESC LIMIT 1`,
		approval.PlanDigest, approval.Actor, approval.TargetDigest, approval.ScopeDigest).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrApprovalUnavailable
	}
	if err != nil {
		return fmt.Errorf("find matching plan approval: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE approvals SET consumed_at = CURRENT_TIMESTAMP
		WHERE approval_id = ? AND consumed_at IS NULL AND julianday(expires_at) > julianday('now')`, id)
	if err != nil {
		return fmt.Errorf("consume plan approval: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check approval consumption: %w", err)
	}
	if changed != 1 {
		return ErrApprovalUnavailable
	}
	if err := insertOperationEvent(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit approval consumption: %w", err)
	}
	return nil
}

func (s *Store) AppendOperationEvent(ctx context.Context, event OperationEvent) error {
	if err := validateEvent(event); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO operation_journal (
		event_id, correlation_id, plan_digest, actor, resource_id, event_type, status, metadata_json, occurred_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		event.ID, event.CorrelationID, event.PlanDigest, event.Actor, event.ResourceID,
		event.EventType, event.Status, event.MetadataJSON); err != nil {
		return fmt.Errorf("append operation journal event: %w", err)
	}
	return nil
}

func (s *Store) ListOperationEvents(ctx context.Context, planDigest string, limit int) ([]OperationEvent, error) {
	if strings.TrimSpace(planDigest) == "" || limit < 1 || limit > 1000 {
		return nil, errors.New("operation event query requires a plan digest and limit from 1 to 1000")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, correlation_id, plan_digest, actor, resource_id,
		event_type, status, metadata_json, occurred_at FROM operation_journal
		WHERE plan_digest = ? ORDER BY occurred_at, rowid LIMIT ?`, planDigest, limit)
	if err != nil {
		return nil, fmt.Errorf("list operation events: %w", err)
	}
	defer rows.Close()
	var events []OperationEvent
	for rows.Next() {
		var event OperationEvent
		if err := rows.Scan(&event.ID, &event.CorrelationID, &event.PlanDigest, &event.Actor,
			&event.ResourceID, &event.EventType, &event.Status, &event.MetadataJSON, &event.OccurredAt); err != nil {
			return nil, fmt.Errorf("scan operation event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate operation events: %w", err)
	}
	return events, nil
}

func (s *Store) AcquireDeploymentLock(ctx context.Context, scopeID, holderID, planDigest, expiresAt string) error {
	if strings.TrimSpace(scopeID) == "" || strings.TrimSpace(holderID) == "" || strings.TrimSpace(planDigest) == "" {
		return errors.New("deployment lock scope, holder and plan are required")
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt)
	now := time.Now()
	if err != nil || !expires.After(now) || expires.After(now.Add(maxDeploymentLockLease)) {
		return errors.New("deployment lock lease must be in the future and at most 15 minutes")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO deployment_locks(scope_id, holder_id, plan_digest, expires_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(scope_id) DO UPDATE SET holder_id=excluded.holder_id,
			plan_digest=excluded.plan_digest, expires_at=excluded.expires_at
		WHERE julianday(deployment_locks.expires_at) <= julianday('now')`,
		scopeID, holderID, planDigest, expiresAt)
	if err != nil {
		return fmt.Errorf("acquire deployment lock: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check deployment lock: %w", err)
	}
	if changed != 1 {
		return ErrDeploymentLocked
	}
	return nil
}

func (s *Store) RefreshDeploymentLock(ctx context.Context, scopeID, holderID, planDigest, expiresAt string) error {
	expires, err := time.Parse(time.RFC3339Nano, expiresAt)
	now := time.Now()
	if err != nil || !expires.After(now) || expires.After(now.Add(maxDeploymentLockLease)) {
		return errors.New("deployment lock lease must be in the future and at most 15 minutes")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE deployment_locks SET expires_at = ?
		WHERE scope_id = ? AND holder_id = ? AND plan_digest = ?
		AND julianday(expires_at) > julianday('now')`, expiresAt, scopeID, holderID, planDigest)
	if err != nil {
		return fmt.Errorf("refresh deployment lock: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check deployment lock refresh: %w", err)
	}
	if changed != 1 {
		return ErrDeploymentLockLost
	}
	return nil
}

func (s *Store) ReleaseDeploymentLock(ctx context.Context, scopeID, holderID, planDigest string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM deployment_locks
		WHERE scope_id = ? AND holder_id = ? AND plan_digest = ?`, scopeID, holderID, planDigest)
	if err != nil {
		return fmt.Errorf("release deployment lock: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check deployment lock release: %w", err)
	}
	if changed != 1 {
		return ErrDeploymentLockLost
	}
	return nil
}

func insertOperationEvent(ctx context.Context, tx *sql.Tx, event OperationEvent) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO operation_journal (
		event_id, correlation_id, plan_digest, actor, resource_id, event_type, status, metadata_json, occurred_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		event.ID, event.CorrelationID, event.PlanDigest, event.Actor, event.ResourceID,
		event.EventType, event.Status, event.MetadataJSON)
	if err != nil {
		return fmt.Errorf("append operation journal event: %w", err)
	}
	return nil
}

func validateEvent(event OperationEvent) error {
	if strings.TrimSpace(event.ID) == "" || strings.TrimSpace(event.CorrelationID) == "" ||
		strings.TrimSpace(event.PlanDigest) == "" || strings.TrimSpace(event.Actor) == "" ||
		strings.TrimSpace(event.ResourceID) == "" || strings.TrimSpace(event.EventType) == "" {
		return errors.New("operation event identifiers are required")
	}
	if event.Status != "ok" && event.Status != "partial" && event.Status != "denied" && event.Status != "error" {
		return errors.New("operation event has invalid status")
	}
	if len(event.MetadataJSON) > 4096 || !json.Valid([]byte(event.MetadataJSON)) {
		return errors.New("operation event metadata must be valid JSON under 4 KiB")
	}
	return nil
}
