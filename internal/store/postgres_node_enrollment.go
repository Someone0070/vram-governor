package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"vram-governor/internal/domain"
)

func (p *PostgresWorkloadStore) CreateNodeEnrollment(ctx context.Context, value *domain.NodeEnrollment) error {
	_, err := p.db.ExecContext(ctx, `INSERT INTO node_enrollments(node_id,node_name,token_hash,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6)`, value.NodeID, value.NodeName, value.TokenHash, value.Status, value.CreatedAt, value.UpdatedAt)
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "23505" {
		return ErrAlreadyExists
	}
	return err
}

func scanNodeEnrollment(row interface{ Scan(...any) error }) (*domain.NodeEnrollment, error) {
	var value domain.NodeEnrollment
	err := row.Scan(&value.NodeID, &value.NodeName, &value.TokenHash, &value.Status, &value.CreatedAt, &value.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (p *PostgresWorkloadStore) GetNodeEnrollmentByHash(ctx context.Context, hash string) (*domain.NodeEnrollment, error) {
	return scanNodeEnrollment(p.db.QueryRowContext(ctx, `SELECT node_id,node_name,token_hash,status,created_at,updated_at FROM node_enrollments WHERE token_hash=$1`, hash))
}

func (p *PostgresWorkloadStore) GetNodeEnrollment(ctx context.Context, nodeID string) (*domain.NodeEnrollment, error) {
	return scanNodeEnrollment(p.db.QueryRowContext(ctx, `SELECT node_id,node_name,token_hash,status,created_at,updated_at FROM node_enrollments WHERE node_id=$1`, nodeID))
}

func (p *PostgresWorkloadStore) ListNodeEnrollments(ctx context.Context) ([]*domain.NodeEnrollment, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT node_id,node_name,token_hash,status,created_at,updated_at FROM node_enrollments ORDER BY node_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := []*domain.NodeEnrollment{}
	for rows.Next() {
		value, err := scanNodeEnrollment(rows)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (p *PostgresWorkloadStore) RevokeNodeEnrollment(ctx context.Context, nodeID string) error {
	result, err := p.db.ExecContext(ctx, `UPDATE node_enrollments SET status='revoked',updated_at=$2 WHERE node_id=$1`, nodeID, time.Now().UTC())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}
