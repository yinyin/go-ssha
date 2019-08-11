package ssha1_test

import (
	"testing"

	"github.com/yinyin/go-ssha/ssha1"
)

func TestHashing_Success(t *testing.T) {
	password := []byte("this-is-password")
	h, err := ssha1.GenerateFromPassword(password, 0)
	if nil != err {
		t.Errorf("failed on GenerateFromPassword: %v", err)
	}
	err = ssha1.CompareHashAndPassword(h, password)
	if nil != err {
		t.Errorf("failed on CompareHashAndPassword: %v", err)
	}
}

func TestHashing_Failed(t *testing.T) {
	password := []byte("this-is-password")
	wrongPassword := []byte("this-is-wrong-password")
	h, err := ssha1.GenerateFromPassword(password, 0)
	if nil != err {
		t.Errorf("failed on GenerateFromPassword: %v", err)
	}
	err = ssha1.CompareHashAndPassword(h, wrongPassword)
	if nil == err {
		t.Errorf("unexpect success on CompareHashAndPassword: %v", err)
	}
}
