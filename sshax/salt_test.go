package sshax

import (
	"bytes"
	"testing"

	"github.com/yinyin/go-ssha/sshax"
)

func TestMakeSaltedBuffer_UseDefault(t *testing.T) {
	d := ([]byte)("this-is-a-test")
	buffer, salt, err := sshax.makeSaltedBuffer(d, 0)
	if nil != err {
		t.Errorf("MakeSaltedBuffer failed: %v", err)
	}
	if len(salt) != sshax.DefaultSaltLen {
		t.Errorf("salt length (%d) != default (%d)", len(salt), sshax.DefaultSaltLen)
	}
	if (len(d) > len(buffer)) || (0 != bytes.Compare(buffer[:len(d)], d)) {
		t.Errorf("given password not prefixed: %v != %v", buffer, d)
	}
	if 0 != bytes.Compare(buffer[len(d):], salt) {
		t.Errorf("salt not suffixed: %v != %v", buffer[len(d):], salt)
	}
}
