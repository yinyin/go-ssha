package sshax_test

import (
	"crypto/md5"
	"crypto/sha1"
	"testing"

	"github.com/yinyin/go-ssha/sshax"
)

func TestHashing_SuccessMD5(t *testing.T) {
	hasher := md5.New()
	password := ([]byte)("this-is-password")
	h, err := sshax.GenerateFromPassword(hasher, password, 0)
	if nil != err {
		t.Errorf("failed on GenerateFromPassword: %v", err)
	}
	hasher.Reset()
	err = sshax.CompareHashAndPassword(hasher, h, password)
	if nil != err {
		t.Errorf("failed on CompareHashAndPassword: %v", err)
	}
}

func TestHashing_FailedMD5(t *testing.T) {
	hasher := md5.New()
	password := ([]byte)("this-is-password")
	wrongPassword := ([]byte)("this-is-password-wrong")
	h, err := sshax.GenerateFromPassword(hasher, password, 0)
	if nil != err {
		t.Errorf("failed on GenerateFromPassword: %v", err)
	}
	hasher.Reset()
	err = sshax.CompareHashAndPassword(hasher, h, wrongPassword)
	if nil == err {
		t.Errorf("unexpect success on CompareHashAndPassword: %v", err)
	}
}

func TestHashing_SuccessSHA1(t *testing.T) {
	hasher := sha1.New()
	password := ([]byte)("this-is-password")
	h, err := sshax.GenerateFromPassword(hasher, password, 0)
	if nil != err {
		t.Errorf("failed on GenerateFromPassword: %v", err)
	}
	hasher.Reset()
	err = sshax.CompareHashAndPassword(hasher, h, password)
	if nil != err {
		t.Errorf("failed on CompareHashAndPassword: %v", err)
	}
}
