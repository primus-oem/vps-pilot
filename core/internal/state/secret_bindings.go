package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func (s *Store) UpsertSecretBinding(ctx context.Context, binding SecretBinding) error {
	if binding.Application == "" || binding.Environment == "" || binding.Host == "" || binding.Service == "" ||
		binding.Name == "" || binding.Reference == "" || binding.Version == "" ||
		(binding.Status != "present" && binding.Status != "pending" && binding.Status != "revoked") {
		return errors.New("secret binding metadata is incomplete")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin secret binding update: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE secret_binding_versions SET status = 'superseded', updated_at = CURRENT_TIMESTAMP
		WHERE application_id = ? AND environment = ? AND host_alias = ? AND service_name = ? AND secret_name = ?
		AND status = 'present' AND version != ?`,
		binding.Application, binding.Environment, binding.Host, binding.Service, binding.Name, binding.Version); err != nil {
		return fmt.Errorf("retire previous secret binding version: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO secret_binding_versions (
		application_id, environment, host_alias, service_name, secret_name,
		reference_digest, version, status, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(application_id, environment, host_alias, service_name, secret_name, version)
	DO UPDATE SET reference_digest=excluded.reference_digest, version=excluded.version,
		status=excluded.status, updated_at=CURRENT_TIMESTAMP`,
		binding.Application, binding.Environment, binding.Host, binding.Service,
		binding.Name, binding.Reference, binding.Version, binding.Status)
	if err != nil {
		return fmt.Errorf("save secret binding metadata: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit secret binding update: %w", err)
	}
	return nil
}

func (s *Store) ListSecretBindings(ctx context.Context, applicationID, environment string) ([]SecretBinding, error) {
	query := `SELECT application_id, environment, host_alias, service_name, secret_name,
		reference_digest, version, status, updated_at FROM secret_binding_versions`
	args := []any{}
	switch {
	case applicationID != "" && environment != "":
		query += ` WHERE application_id = ? AND environment = ?`
		args = append(args, applicationID, environment)
	case applicationID != "":
		query += ` WHERE application_id = ?`
		args = append(args, applicationID)
	case environment != "":
		query += ` WHERE environment = ?`
		args = append(args, environment)
	}
	query += ` ORDER BY application_id, environment, host_alias, service_name, secret_name, version`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list secret binding metadata: %w", err)
	}
	defer rows.Close()
	bindings := []SecretBinding{}
	for rows.Next() {
		var binding SecretBinding
		if err := rows.Scan(&binding.Application, &binding.Environment, &binding.Host, &binding.Service,
			&binding.Name, &binding.Reference, &binding.Version, &binding.Status, &binding.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan secret binding metadata: %w", err)
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate secret binding metadata: %w", err)
	}
	return bindings, nil
}

func (s *Store) GetSecretBinding(ctx context.Context, applicationID, environment, host, service, name string) (SecretBinding, error) {
	var binding SecretBinding
	err := s.db.QueryRowContext(ctx, `SELECT application_id, environment, host_alias, service_name, secret_name,
		reference_digest, version, status, updated_at FROM secret_binding_versions
		WHERE application_id = ? AND environment = ? AND host_alias = ? AND service_name = ? AND secret_name = ?
		AND status = 'present' ORDER BY updated_at DESC LIMIT 1`,
		applicationID, environment, host, service, name).Scan(
		&binding.Application, &binding.Environment, &binding.Host, &binding.Service, &binding.Name,
		&binding.Reference, &binding.Version, &binding.Status, &binding.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return SecretBinding{}, errors.New("secret binding not found")
	}
	if err != nil {
		return SecretBinding{}, fmt.Errorf("get secret binding metadata: %w", err)
	}
	return binding, nil
}

func (s *Store) RevokeSecretBinding(ctx context.Context, applicationID, environment, host, service, name string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE secret_binding_versions SET status = 'revoked', updated_at = CURRENT_TIMESTAMP
		WHERE application_id = ? AND environment = ? AND host_alias = ? AND service_name = ? AND secret_name = ?
		AND status = 'present'`,
		applicationID, environment, host, service, name)
	if err != nil {
		return fmt.Errorf("revoke secret binding metadata: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check secret binding revocation: %w", err)
	}
	if changed != 1 {
		return errors.New("secret binding not found")
	}
	return nil
}
