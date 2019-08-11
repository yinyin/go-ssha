package ssha512

import (
	"crypto/sha512"

	"github.com/yinyin/go-ssha/sshax"
)

// GenerateFromPassword returns the SSHA-512 hash of the password with the given
// salt length. If the length given is less than MinSaltLen, the salt length
// will be set to DefaultSaltLen, instead.
func GenerateFromPassword(password []byte, saltLength int) ([]byte, error) {
	hasher := sha512.New()
	return sshax.GenerateFromPassword(hasher, password, saltLength)
}

// CompareHashAndPassword compares a SSHA-512 hashed password with its possible
// plaintext equivalent. Returns nil on success, or an error on failure.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	hasher := sha512.New()
	return sshax.CompareHashAndPassword(hasher, hashedPassword, password)
}
