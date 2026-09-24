/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EnvFileName is the file in the user's home directory that New loads into
// the environment before reading any ALERTER_* variable.
const EnvFileName = ".alerter"

// loadEnvFile reads ~/.alerter, when it exists, and sets each ALERTER_*
// variable it names that is not already set in the environment, so the
// process environment (a service unit, a shell export) overrides the file.
// Other keys are ignored: a library must not change the host's environment
// (PATH, proxies, certificate paths) behind its back. The format
// is one KEY=VALUE per line; blank lines and lines starting with # are
// ignored, a leading "export " is allowed, and a value may be wrapped in
// single or double quotes. A missing file or home directory is not an error;
// an unreadable or malformed file is.
func loadEnvFile() error {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil //nolint:nilerr // no home directory means no file to load
	}
	path := filepath.Join(home, EnvFileName)
	f, err := os.Open(path) //nolint:gosec // fixed file in the user's home
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("alerter: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if n == 1 {
			line = strings.TrimPrefix(line, "\uFEFF") // byte order mark
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" || strings.ContainsAny(key, " \t") {
			return fmt.Errorf("alerter: %s line %d: want KEY=VALUE", path, n)
		}
		if !strings.HasPrefix(key, "ALERTER_") {
			continue
		}
		if _, set := os.LookupEnv(key); set {
			continue
		}
		if err := os.Setenv(key, unquote(strings.TrimSpace(value))); err != nil {
			return fmt.Errorf("alerter: %s line %d: %w", path, n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("alerter: read %s: %w", path, err)
	}
	return nil
}

// unquote strips one pair of matching single or double quotes.
func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
