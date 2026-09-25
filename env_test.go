/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withHome points HOME at a fresh directory holding .alerter with content
// (no file when content is empty).
func withHome(t *testing.T, content string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if content != "" {
		if err := os.WriteFile(filepath.Join(home, EnvFileName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestLoadEnvFileMissing(t *testing.T) {
	withHome(t, "")
	if err := loadEnvFile(); err != nil {
		t.Errorf("missing file: %v", err)
	}
}

func TestLoadEnvFileNoHome(t *testing.T) {
	t.Setenv("HOME", "")
	if err := loadEnvFile(); err != nil {
		t.Errorf("no home: %v", err)
	}
}

func TestLoadEnvFileParses(t *testing.T) {
	keys := []string{"ALERTER_T_PLAIN", "ALERTER_T_EXPORT", "ALERTER_T_DQ", "ALERTER_T_SQ",
		"ALERTER_T_EQ", "ALERTER_T_EMPTY", "ALERTER_T_SPACED", "ALERTER_T_PRESET"}
	unsetAfter(t, keys...)
	t.Setenv("ALERTER_T_PRESET", "from-environment")
	withHome(t, `
# a comment
ALERTER_T_PLAIN=plain
export ALERTER_T_EXPORT=exported
ALERTER_T_DQ="double quoted # not a comment"
ALERTER_T_SQ='single'
ALERTER_T_EQ=a=b=c
ALERTER_T_EMPTY=
  ALERTER_T_SPACED  =  spaced value
ALERTER_T_PRESET=from-file
`)
	if err := loadEnvFile(); err != nil {
		t.Fatalf("loadEnvFile: %v", err)
	}
	want := map[string]string{
		"ALERTER_T_PLAIN":  "plain",
		"ALERTER_T_EXPORT": "exported",
		"ALERTER_T_DQ":     "double quoted # not a comment",
		"ALERTER_T_SQ":     "single",
		"ALERTER_T_EQ":     "a=b=c",
		"ALERTER_T_EMPTY":  "",
		"ALERTER_T_SPACED": "spaced value",
		"ALERTER_T_PRESET": "from-environment", // the environment wins
	}
	for k, v := range want {
		got, ok := os.LookupEnv(k)
		if !ok || got != v {
			t.Errorf("%s = %q (set %v), want %q", k, got, ok, v)
		}
	}
}

func TestLoadEnvFileOnlyAlerterKeys(t *testing.T) {
	unsetAfter(t, "ALERTER_T_BOM", "ALERTER_T_KEPT", "NOT_ALERTER_T")
	withHome(t, "\uFEFFALERTER_T_BOM=bom\nNOT_ALERTER_T=x\nALERTER_T_KEPT=y\n")
	if err := loadEnvFile(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ALERTER_T_BOM") != "bom" || os.Getenv("ALERTER_T_KEPT") != "y" {
		t.Errorf("ALERTER_ keys not loaded: %q %q", os.Getenv("ALERTER_T_BOM"), os.Getenv("ALERTER_T_KEPT"))
	}
	if _, set := os.LookupEnv("NOT_ALERTER_T"); set {
		t.Error("a key without the ALERTER_ prefix was loaded into the environment")
	}
}

func TestLoadEnvFileMalformed(t *testing.T) {
	for _, line := range []string{"NOEQUALS", "=value", "TWO WORDS=x"} {
		t.Run(line, func(t *testing.T) {
			withHome(t, "# ok\n"+line+"\n")
			err := loadEnvFile()
			if err == nil || !strings.Contains(err.Error(), "line 2") {
				t.Errorf("error = %v, want a line 2 error", err)
			}
		})
	}
}

func TestLoadEnvFileUnreadable(t *testing.T) {
	home := withHome(t, "")
	// A directory in place of the file opens but cannot be read.
	if err := os.Mkdir(filepath.Join(home, EnvFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := loadEnvFile(); err == nil {
		t.Error("expected a read error")
	}
}

func TestLoadEnvFileUnopenable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	withHome(t, "ALERTER_T_X=1\n")
	if err := os.Chmod(filepath.Join(os.Getenv("HOME"), EnvFileName), 0); err != nil {
		t.Fatal(err)
	}
	if err := loadEnvFile(); err == nil {
		t.Error("expected an open error")
	}
}

func TestNewLoadsEnvFile(t *testing.T) {
	unsetAfter(t, EnvLogFile)
	path := filepath.Join(t.TempDir(), "from-file.txt")
	withHome(t, EnvLogFile+"="+path+"\n")
	d, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.Priority("t", "d")
	if err := d.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), "PRIORITY  t: d") { //nolint:gosec // test temp file
		t.Errorf("log named in ~/.alerter: %q, %v", b, err)
	}
}

func TestNewFailsOnBadEnvFile(t *testing.T) {
	withHome(t, "garbage\n")
	if _, err := New(); err == nil {
		t.Error("New accepted a malformed ~/.alerter")
	}
}

func TestNewFailsOnBadChannel(t *testing.T) {
	unsetAfter(t, EnvPushoverToken, EnvPushoverDest)
	withHome(t, EnvPushoverToken+"=tok\n")
	_, err := New(WithLogFile(filepath.Join(t.TempDir(), "a.txt")))
	if err == nil || !strings.Contains(err.Error(), EnvPushoverDest) {
		t.Errorf("error = %v, want it to name %s", err, EnvPushoverDest)
	}
}
