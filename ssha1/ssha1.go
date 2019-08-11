package ssha1

import (
	"crypto/sha1"

	"github.com/yinyin/go-ssha/sshax"
)

// GenerateFromPassword returns the SSHA (SSHA-1) hash of the password with the
// given salt length. If the length given is less than MinSaltLen, the salt
// length will be set to DefaultSaltLen, instead.
func GenerateFromPassword(password []byte, saltLength int) ([]byte, error) {
	hasher := sha1.New()
	return sshax.GenerateFromPassword(hasher, password, saltLength)
}

// CompareHashAndPassword compares a SSHA (SSHA-1) hashed password with its
// possible plaintext equivalent. Returns nil on success, or an error on
// failure.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	hasher := sha1.New()
	return sshax.CompareHashAndPassword(hasher, hashedPassword, password)
}
