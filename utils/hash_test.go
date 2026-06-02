package utils

import "testing"

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPasswordHash("password123", hash) {
		t.Fatal("password should match hash")
	}
	if CheckPasswordHash("wrong", hash) {
		t.Fatal("wrong password should not match")
	}
}
