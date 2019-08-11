package ssha_test

import (
	"testing"

	ssha "github.com/yinyin/go-ssha"
)

func TestSSHA_SuccessOnFly(t *testing.T) {
	password := []byte("this-is-password")
	h, err := ssha.GenerateSSHAFromPassword(password, 0)
	if nil != err {
		t.Errorf("failed on GenerateSSHAFromPassword: %v", err)
	}
	err = ssha.CompareHashAndPassword(h, password)
	if nil != err {
		t.Errorf("failed on CompareHashAndPassword: %v", err)
	}
}

func TestSSHA_SuccessInterop(t *testing.T) {
	password := []byte("this-is-password")
	h := []byte("{SSHA}m4LC8ur2sHut1uWtFdHYiUWxEaxw0wnr")
	err := ssha.CompareHashAndPassword(h, password)
	if nil != err {
		t.Errorf("failed on CompareHashAndPassword: %v", err)
	}
}

func TestSSHA512_SuccessOnFly(t *testing.T) {
	password := []byte("this-is-password")
	h, err := ssha.GenerateSSHA512FromPassword(password, 0)
	if nil != err {
		t.Errorf("failed on GenerateSSHA512FromPassword: %v", err)
	}
	err = ssha.CompareHashAndPassword(h, password)
	if nil != err {
		t.Errorf("failed on CompareHashAndPassword: %v", err)
	}
}
