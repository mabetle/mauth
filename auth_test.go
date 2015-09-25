package mauth_test

import (
	"github.com/mabetle/mauth"
	"testing"
)

func init() {
	mauth.InitAuthMap()
}

func TestAuth(t *testing.T) {
	if !mauth.IsCanAccessRes("/admin", "admin") {
		t.Error("")
	}

}
