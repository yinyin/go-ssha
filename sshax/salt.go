package sshax

import (
	"crypto/rand"
	"hash"
)

// MinSaltLen is the minimum acceptable salt length as passed in to
// GenerateFromPassword.
const MinSaltLen int = 4

// DefaultSaltLen is the salt length that will be set if a salt length less
// than MinSaltLen is passed into GenerateFromPassword.
const DefaultSaltLen int = 8

// makeSaltedBuffer create and return byte slice with given password and salt
// bytes in created buffer.
func makeSaltedBuffer(password []byte, saltLength int) (buffer, salt []byte, err error) {
	if saltLength < MinSaltLen {
		saltLength = DefaultSaltLen
	}
	salt = make([]byte, saltLength)
	if _, err = rand.Read(salt); nil != err {
		return nil, nil, err
	}
	if l := len(password); l > 0 {
		buffer = make([]byte, 0, l+saltLength)
		buffer = append(buffer, password...)
	}
	buffer = append(buffer, salt...)
	return
}

func makeSalt(saltLength int) (salt []byte, err error) {
	if saltLength < MinSaltLen {
		saltLength = DefaultSaltLen
	}
	salt = make([]byte, saltLength)
	if _, err = rand.Read(salt); nil != err {
		return nil, err
	}
	return
}

func saltedHash(hasher hash.Hash, password, salt []byte) []byte {
	var buffer []byte
	buffer = make([]byte, 0, len(password)+len(salt))
	buffer = append(buffer, password...)
	buffer = append(buffer, salt...)
	hasher.Write(buffer)
	return hasher.Sum(nil)
}
