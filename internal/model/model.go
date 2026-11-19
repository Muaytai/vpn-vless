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
