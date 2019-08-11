package sshax

import (
	"errors"
)

// ErrHashTooShort returned when given hashedPassword is too shorted.
var ErrHashTooShort = errors.New("hashedPassword too short to be a hashed password")

// ErrMismatchedHashAndPassword returned when given hashedPassword and
// password not match.
var ErrMismatchedHashAndPassword = errors.New("hashedPassword is not the hash of the given password")
