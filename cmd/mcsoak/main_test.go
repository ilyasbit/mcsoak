package main

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestHelpersSmoke(t *testing.T) {
	t.Setenv("MCSOAK_TEST_STR", "hello")
	if got := getEnv("MCSOAK_TEST_STR", "default"); got != "hello" {
		t.Fatalf("getEnv = %q, want %q", got, "hello")
	}
	if got := getEnv("MCSOAK_TEST_UNSET", "default"); got != "default" {
		t.Fatalf("getEnv unset = %q, want %q", got, "default")
	}

	t.Setenv("MCSOAK_TEST_BOOL", "true")
	if !getEnvBool("MCSOAK_TEST_BOOL", false) {
		t.Fatalf("getEnvBool(true) = false, want true")
	}
	if getEnvBool("MCSOAK_TEST_BOOL_UNSET", false) {
		t.Fatalf("getEnvBool(unset) = true, want false")
	}

	if got := parseListenPort(":8443"); got != 8443 {
		t.Fatalf("parseListenPort(:8443) = %d, want 8443", got)
	}
	if got := parseListenPort("invalid"); got != 0 {
		t.Fatalf("parseListenPort(invalid) = %d, want 0", got)
	}
}
