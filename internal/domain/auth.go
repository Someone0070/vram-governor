package domain

import "time"

// BrowserSession is the durable, server-side representation of a browser
// login. Session and CSRF secrets are stored only as SHA-256 digests; raw
// values exist only in the browser cookie/login response.
type BrowserSession struct {
	IDHash              string    `json:"id_hash"`
	PrincipalID         string    `json:"principal_id"`
	Plane               string    `json:"plane"`
	OwnerID             string    `json:"owner_id"`
	Scopes              []string  `json:"scopes"`
	Adapters            []string  `json:"adapters"`
	NodeID              string    `json:"node_id,omitempty"`
	MaxPriority         int       `json:"max_priority"`
	MaxIncidentSeverity string    `json:"max_incident_severity,omitempty"`
	EgressPolicy        string    `json:"egress_policy"`
	ConcurrencyLimit    int       `json:"concurrency_limit,omitempty"`
	BudgetCents         int64     `json:"budget_cents,omitempty"`
	PreemptionBudget    int       `json:"preemption_budget,omitempty"`
	Kind                string    `json:"kind"`
	CSRFHash            string    `json:"csrf_hash"`
	ExpiresAt           time.Time `json:"expires_at"`
	CreatedAt           time.Time `json:"created_at"`
}
