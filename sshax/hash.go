package sshax

import (
	"bytes"
	"encoding/base64"
	"hash"
)

func packHash(digest, salt []byte) (result []byte) {
	l := len(digest) + len(salt)
	buffer := make([]byte, 0, l)
	buffer = append(buffer, digest...)
	buffer = append(buffer, salt...)
	result = make([]byte, base64.StdEncoding.EncodedLen(l))
	base64.StdEncoding.Encode(result, buffer)
	return
}

// GenerateFromPassword returns the hash of the password with salt of the given
// salt length. If the length given is less than MinSaltLen, the salt length
// will be set to DefaultSaltLen, instead.
func GenerateFromPassword(hasher hash.Hash, password []byte, saltLength int) (result []byte, err error) {
	salt, err := makeSalt(saltLength)
	if nil != err {
		return
	}
	digest := saltedHash(hasher, password, salt)
	result = packHash(digest, salt)
	return
}

func unpackHash(hashedPassword []byte, digestLen int) ([]byte, error) {
	unpackedHashLen := base64.StdEncoding.DecodedLen(len(hashedPassword))
	if unpackedHashLen < digestLen {
		return nil, ErrHashTooShort
	}
	unpackedHash := make([]byte, unpackedHashLen)
	unpackedHashLen, err := base64.StdEncoding.Decode(unpackedHash, hashedPassword)
	if nil != err {
		return nil, err
	}
	if unpackedHashLen < digestLen {
		return nil, ErrHashTooShort
	}
	return unpackedHash[:unpackedHashLen], nil
}

// CompareHashAndPassword compares a hashed password with its possible
// plaintext equivalent. Returns nil on success, or an error on failure.
func CompareHashAndPassword(hasher hash.Hash, hashedPassword, password []byte) error {
	digestLen := hasher.Size()
	unpackedHash, err := unpackHash(hashedPassword, digestLen)
	if nil != err {
		return err
	}
	salt := unpackedHash[digestLen:]
	checkDigest := saltedHash(hasher, password, salt)
	if 0 != bytes.Compare(unpackedHash[:digestLen], checkDigest) {
		return ErrMismatchedHashAndPassword
	}
	return nil
}
