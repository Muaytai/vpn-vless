package model

import "time"

type Server struct {
	Endpoint   string
	Port       int
	ServerName string
	Target     string
	PrivateKey string
	PublicKey  string
	ShortID    string
	CreatedAt  time.Time
}

type User struct {
	Name      string
	UUID      string
	Active    bool
	CreatedAt time.Time
	RevokedAt *time.Time
}

// IsActive reports whether the user has not been revoked.
func (u User) IsActive() bool { return u.Active && u.RevokedAt == nil }
