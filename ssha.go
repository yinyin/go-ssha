package ssha

import (
	"bytes"
	"errors"

	"github.com/yinyin/go-ssha/ssha1"
	"github.com/yinyin/go-ssha/ssha512"
)

// ErrUnknownHashScheme indicate the hash schema in hashed password is not supported.
var ErrUnknownHashScheme = errors.New("unknown hash scheme")

var ssha1Prefix = ([]byte)("{SSHA}")
var ssha512Prefix = ([]byte)("{SSHA512}")

func prependSchemePrefix(prefix, hashedPassword []byte) (result []byte) {
	result = make([]byte, 0, len(prefix)+len(hashedPassword))
	result = append(result, prefix...)
	result = append(result, hashedPassword...)
	return
}

// GenerateSSHAFromPassword returns the hash of the password with salt of the given
// salt length. If the length given is less than MinSaltLen, the salt length
// will be set to DefaultSaltLen, instead.
func GenerateSSHAFromPassword(password []byte, saltLength int) (result []byte, err error) {
	h, err := ssha1.GenerateFromPassword(password, saltLength)
	if nil != err {
		return
	}
	result = prependSchemePrefix(ssha1Prefix, h)
	return
}

// GenerateSSHA512FromPassword returns the hash of the password with salt of the given
// salt length. If the length given is less than MinSaltLen, the salt length
// will be set to DefaultSaltLen, instead.
func GenerateSSHA512FromPassword(password []byte, saltLength int) (result []byte, err error) {
	h, err := ssha512.GenerateFromPassword(password, saltLength)
	if nil != err {
		return
	}
	result = prependSchemePrefix(ssha512Prefix, h)
	return
}

// CompareHashAndPassword compares a hashed password with its possible
// plaintext equivalent. Returns nil on success, or an error on failure.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	switch {
	case bytes.HasPrefix(hashedPassword, ssha1Prefix):
		h := hashedPassword[len(ssha1Prefix):]
		return ssha1.CompareHashAndPassword(h, password)
	case bytes.HasPrefix(hashedPassword, ssha512Prefix):
		h := hashedPassword[len(ssha512Prefix):]
		return ssha512.CompareHashAndPassword(h, password)
	}
	return ErrUnknownHashScheme
}
