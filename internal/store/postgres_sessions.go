package store

import (
	"context"
	"encoding/json"

	"vram-governor/internal/domain"
)

func (p *PostgresWorkloadStore) CreateBrowserSession(ctx context.Context, session *domain.BrowserSession) error {
	body, err := json.Marshal(session)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO browser_sessions(id_hash,principal_id,kind,expires_at,body,created_at) VALUES($1,$2,$3,$4,$5,$6)`, session.IDHash, session.PrincipalID, session.Kind, session.ExpiresAt, body, session.CreatedAt)
	return err
}

func (p *PostgresWorkloadStore) GetBrowserSession(ctx context.Context, idHash string) (*domain.BrowserSession, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM browser_sessions WHERE id_hash=$1`, idHash).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var session domain.BrowserSession
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (p *PostgresWorkloadStore) DeleteBrowserSession(ctx context.Context, idHash string) error {
	_, err := p.db.ExecContext(ctx, `DELETE FROM browser_sessions WHERE id_hash=$1`, idHash)
	return err
}
