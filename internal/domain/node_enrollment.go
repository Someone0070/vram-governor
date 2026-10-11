package domain

import "time"

// NodeEnrollment is the durable authority for self-declared node credentials.
// TokenHash is never returned by an HTTP endpoint.
type NodeEnrollment struct {
	NodeID    string    `json:"node_id"`
	NodeName  string    `json:"node_name"`
	TokenHash string    `json:"-"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
