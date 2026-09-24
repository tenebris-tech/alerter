/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// realHome is the user's home directory before TestMain replaced it, live is
// ALERTER_LIVE_TEST=1, and liveEnv holds the ALERTER_* variables TestMain
// removed; only the live test uses them.
var (
	realHome string
	live     bool
	liveEnv  = map[string]string{}
)

// TestMain isolates the suite from the operator's configuration: HOME points
// at an empty directory, so ~/.alerter is never loaded, and every ALERTER_*
// variable is removed, so no test reaches a real service by accident.
func TestMain(m *testing.M) {
	realHome, _ = os.UserHomeDir()
	live = os.Getenv("ALERTER_LIVE_TEST") == "1"
	home, err := os.MkdirTemp("", "alerter-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.Setenv("HOME", home); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, kv := range os.Environ() {
		if k, v, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "ALERTER_") {
			liveEnv[k] = v
			_ = os.Unsetenv(k)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(home)
	os.Exit(code)
}

// unsetAfter makes the variables unset now and again when the test ends, so
// values that loadEnvFile sets with os.Setenv do not leak between tests.
func unsetAfter(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		t.Setenv(k, "") // registers the restore to "unset"
		_ = os.Unsetenv(k)
	}
}

// setEnv sets each KEY=VALUE pair for the duration of the test.
func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}
