package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"

	"vram-governor/internal/domain"
)

func marshalSnapshot(value any) ([]byte, error) { return json.Marshal(value) }

func unmarshalSnapshot(body []byte, value any) error { return json.Unmarshal(body, value) }

func (p *PostgresWorkloadStore) UpsertNode(ctx context.Context, node *domain.Node) (*domain.Node, error) {
	// The row lock below is the concurrency boundary. SERIALIZABLE caused
	// heartbeat, telemetry, and liveness writers for the same node to abort
	// each other under normal load instead of waiting for the row.
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var existingBody []byte
	err = tx.QueryRowContext(ctx, `SELECT body FROM controller_nodes WHERE id=$1 FOR UPDATE`, node.ID).Scan(&existingBody)
	if err == nil {
		var existing domain.Node
		if err := unmarshalSnapshot(existingBody, &existing); err != nil {
			return nil, err
		}
		node.RegisteredAt = existing.RegisteredAt
	} else if err == sql.ErrNoRows {
		node.RegisteredAt = now
	} else {
		return nil, err
	}
	node.UpdatedAt = now
	body, err := marshalSnapshot(node)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO controller_nodes(id,body,updated_at) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body,updated_at=EXCLUDED.updated_at`, node.ID, body, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return cloneNode(node), nil
}

func (p *PostgresWorkloadStore) GetNode(ctx context.Context, id string) (*domain.Node, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM controller_nodes WHERE id=$1`, id).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var node domain.Node
	if err := unmarshalSnapshot(body, &node); err != nil {
		return nil, err
	}
	return cloneNode(&node), nil
}

func (p *PostgresWorkloadStore) ListNodes(ctx context.Context) ([]*domain.Node, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM controller_nodes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.Node
	for rows.Next() {
		var body []byte
		var node domain.Node
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		if err := unmarshalSnapshot(body, &node); err != nil {
			return nil, err
		}
		result = append(result, cloneNode(&node))
	}
	return result, rows.Err()
}

func (p *PostgresWorkloadStore) UpdateObserved(ctx context.Context, id string, update func(*domain.Observed, *[]domain.Accelerator)) error {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var body []byte
	if err := tx.QueryRowContext(ctx, `SELECT body FROM controller_nodes WHERE id=$1 FOR UPDATE`, id).Scan(&body); err != nil {
		return translateSQLError(err)
	}
	var node domain.Node
	if err := unmarshalSnapshot(body, &node); err != nil {
		return err
	}
	update(&node.Observed, &node.Accelerators)
	node.UpdatedAt = time.Now().UTC()
	body, err = marshalSnapshot(&node)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE controller_nodes SET body=$2,updated_at=$3 WHERE id=$1`, id, body, node.UpdatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *PostgresWorkloadStore) UpdateDesired(ctx context.Context, id string, update func(*domain.Desired, *domain.SchedulingState)) error {
	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var body []byte
	if err := tx.QueryRowContext(ctx, `SELECT body FROM controller_nodes WHERE id=$1 FOR UPDATE`, id).Scan(&body); err != nil {
		return translateSQLError(err)
	}
	var node domain.Node
	if err := unmarshalSnapshot(body, &node); err != nil {
		return err
	}
	update(&node.Desired, &node.SchedulingState)
	node.UpdatedAt = time.Now().UTC()
	body, err = marshalSnapshot(&node)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE controller_nodes SET body=$2,updated_at=$3 WHERE id=$1`, id, body, node.UpdatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *PostgresWorkloadStore) DeleteNode(ctx context.Context, id string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM controller_nodes WHERE id=$1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM controller_engines WHERE node_id=$1`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM controller_performance_profiles WHERE node_id=$1`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (p *PostgresWorkloadStore) UpsertEngine(ctx context.Context, engine *domain.EngineInstance) (*domain.EngineInstance, error) {
	body, err := marshalSnapshot(engine)
	if err != nil {
		return nil, err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO controller_engines(id,node_id,body,updated_at) VALUES($1,$2,$3,now()) ON CONFLICT(id) DO UPDATE SET node_id=EXCLUDED.node_id,body=EXCLUDED.body,updated_at=EXCLUDED.updated_at`, engine.ID, engine.NodeID, body)
	if err != nil {
		return nil, err
	}
	copy := *engine
	return &copy, nil
}

func (p *PostgresWorkloadStore) ListEnginesForNode(ctx context.Context, nodeID string) ([]*domain.EngineInstance, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM controller_engines WHERE node_id=$1 ORDER BY id`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.EngineInstance
	for rows.Next() {
		var body []byte
		var engine domain.EngineInstance
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		if err := unmarshalSnapshot(body, &engine); err != nil {
			return nil, err
		}
		result = append(result, &engine)
	}
	return result, rows.Err()
}

func (p *PostgresWorkloadStore) DeleteEngine(ctx context.Context, id string) error {
	result, err := p.db.ExecContext(ctx, `DELETE FROM controller_engines WHERE id=$1`, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PostgresWorkloadStore) SaveProfile(ctx context.Context, nodeID string, profile *domain.PerformanceProfile) (*domain.PerformanceProfile, error) {
	body, err := marshalSnapshot(profile)
	if err != nil {
		return nil, err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO controller_performance_profiles(node_id,id,body,measured_at) VALUES($1,$2,$3,$4) ON CONFLICT(node_id,id) DO UPDATE SET body=EXCLUDED.body,measured_at=EXCLUDED.measured_at`, nodeID, profile.ID, body, profile.MeasuredAt)
	if err != nil {
		return nil, err
	}
	copy := *profile
	return &copy, nil
}

func (p *PostgresWorkloadStore) listProfiles(ctx context.Context, nodeID string) ([]*domain.PerformanceProfile, error) {
	query := `SELECT body FROM controller_performance_profiles`
	var args []any
	if nodeID != "" {
		query += ` WHERE node_id=$1`
		args = append(args, nodeID)
	}
	query += ` ORDER BY measured_at DESC,id`
	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.PerformanceProfile
	for rows.Next() {
		var body []byte
		var profile domain.PerformanceProfile
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		if err := unmarshalSnapshot(body, &profile); err != nil {
			return nil, err
		}
		result = append(result, &profile)
	}
	return result, rows.Err()
}

func (p *PostgresWorkloadStore) ListProfilesForNode(ctx context.Context, nodeID string) ([]*domain.PerformanceProfile, error) {
	return p.listProfiles(ctx, nodeID)
}

func (p *PostgresWorkloadStore) ListAllProfiles(ctx context.Context) ([]*domain.PerformanceProfile, error) {
	return p.listProfiles(ctx, "")
}

func (p *PostgresWorkloadStore) UpsertJob(ctx context.Context, job *domain.Job) (*domain.Job, error) {
	body, err := marshalSnapshot(job)
	if err != nil {
		return nil, err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO controller_jobs(id,body,updated_at) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body,updated_at=EXCLUDED.updated_at`, job.ID, body, job.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return cloneJob(job), nil
}

func (p *PostgresWorkloadStore) GetJob(ctx context.Context, id string) (*domain.Job, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM controller_jobs WHERE id=$1`, id).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var job domain.Job
	if err := unmarshalSnapshot(body, &job); err != nil {
		return nil, err
	}
	return cloneJob(&job), nil
}

func (p *PostgresWorkloadStore) ListJobs(ctx context.Context) ([]*domain.Job, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM controller_jobs ORDER BY updated_at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.Job
	for rows.Next() {
		var body []byte
		var job domain.Job
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		if err := unmarshalSnapshot(body, &job); err != nil {
			return nil, err
		}
		result = append(result, cloneJob(&job))
	}
	return result, rows.Err()
}

func (p *PostgresWorkloadStore) UpsertWorkItem(ctx context.Context, item *domain.WorkItem) (*domain.WorkItem, error) {
	body, err := marshalSnapshot(item)
	if err != nil {
		return nil, err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO controller_work_items(job_id,item_id,operation_version,body,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(job_id,item_id,operation_version) DO UPDATE SET body=EXCLUDED.body,updated_at=EXCLUDED.updated_at`, item.JobID, item.ItemID, item.OperationVersion, body, item.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return cloneWorkItem(item), nil
}

func (p *PostgresWorkloadStore) GetWorkItem(ctx context.Context, jobID, itemID, operationVersion string) (*domain.WorkItem, error) {
	var body []byte
	if err := p.db.QueryRowContext(ctx, `SELECT body FROM controller_work_items WHERE job_id=$1 AND item_id=$2 AND operation_version=$3`, jobID, itemID, operationVersion).Scan(&body); err != nil {
		return nil, translateSQLError(err)
	}
	var item domain.WorkItem
	if err := unmarshalSnapshot(body, &item); err != nil {
		return nil, err
	}
	return cloneWorkItem(&item), nil
}

func (p *PostgresWorkloadStore) ListWorkItemsForJob(ctx context.Context, jobID string) ([]*domain.WorkItem, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT body FROM controller_work_items WHERE job_id=$1`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []*domain.WorkItem
	for rows.Next() {
		var body []byte
		var item domain.WorkItem
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		if err := unmarshalSnapshot(body, &item); err != nil {
			return nil, err
		}
		result = append(result, cloneWorkItem(&item))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Seq < result[j].Seq })
	return result, rows.Err()
}

var _ Store = (*PostgresWorkloadStore)(nil)
