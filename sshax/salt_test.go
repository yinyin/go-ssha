package sshax

import (
	"bytes"
	"crypto/md5"
	"testing"
)

func TestMakeSalted_UseDefault(t *testing.T) {
	salt, err := makeSalt(0)
	if nil != err {
		t.Errorf("MakeSalt failed: %v", err)
	}
	if len(salt) != DefaultSaltLen {
		t.Errorf("salt length (%d) != default (%d)", len(salt), DefaultSaltLen)
	}
}

func TestSaltedHash_MD5(t *testing.T) {
	hasher := md5.New()
	password := ([]byte)("p-a-s-s-w-o-r-d")
	salt := ([]byte)(".s.a.l.t.")
	combined := ([]byte)("p-a-s-s-w-o-r-d.s.a.l.t.")
	h := saltedHash(hasher, password, salt)
	c := md5.Sum(combined)
	if 0 != bytes.Compare(h, c[:]) {
		t.Errorf("hash mismatch: %v, %v", h, c)
	}
}
