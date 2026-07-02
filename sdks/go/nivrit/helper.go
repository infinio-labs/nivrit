package nivrit

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// Per-platform helper binaries, dropped in at release time by
// scripts/embed-helpers.sh. The dev tree ships only bin/.keep, so the embed
// always compiles and extractHelper() simply finds nothing — callers then fall
// back to NIVRIT_CRYPTO_HELPER or a local cargo build.
//
// ponytail: embeds every platform's binary (~4MB total at ~0.8MB each) into the
// consumer binary. Switch to //go:build-tagged per-platform embeds if size matters.
//
//go:embed all:bin
var helperFS embed.FS

var errNoEmbeddedHelper = errors.New("no embedded helper for this platform")

func embeddedHelperName() string {
	if runtime.GOOS == "windows" {
		return "nivrit-crypto-helper.exe"
	}
	return "nivrit-crypto-helper"
}

// extractHelper writes the embedded binary for the current platform to a
// content-addressed path under the user cache dir and returns it. The sha in the
// path pins the binary to its exact bytes, so a version bump can never resolve a
// stale helper.
func extractHelper() (string, error) {
	name := embeddedHelperName()
	data, err := helperFS.ReadFile("bin/" + runtime.GOOS + "_" + runtime.GOARCH + "/" + name)
	if err != nil {
		return "", errNoEmbeddedHelper
	}
	sum := sha256.Sum256(data)
	dir := filepath.Join(cacheRoot(), "nivrit-crypto-helper", hex.EncodeToString(sum[:8]))
	target := filepath.Join(dir, name)
	if _, err := os.Stat(target); err == nil {
		return target, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, data, 0o700); err != nil {
		return "", err
	}
	return target, os.Rename(tmp, target)
}

func cacheRoot() string {
	if d, err := os.UserCacheDir(); err == nil {
		return d
	}
	return os.TempDir()
}
