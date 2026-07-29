// Package updater implements in-place self-upgrade from GitHub releases.
//
// Flow: resolve the latest release tag (via the /releases/latest redirect, no
// API token needed), download the platform asset and SHA256SUMS, verify the
// checksum, extract the binary, stop the service if running, swap the
// executable (rename-then-replace, which also works for a running binary on
// Windows), and restart the service if it was running.
package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	svc "github.com/CVE-Todo/CVETodo-agent/internal/service"
)

const (
	repo = "CVE-Todo/CVETodo-agent"
	// latestURL redirects to .../releases/tag/<tag>; we read the Location
	// header instead of consuming the GitHub API rate limit.
	latestURL = "https://github.com/" + repo + "/releases/latest"
)

var httpClient = &http.Client{Timeout: 5 * time.Minute}

// LatestTag resolves the tag name of the newest published release.
func LatestTag() (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow; we want the Location
		},
	}
	req, err := http.NewRequest(http.MethodGet, latestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "cvetodo-agent-updater")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("checking latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	loc := resp.Header.Get("Location")
	idx := strings.LastIndex(loc, "/tag/")
	if resp.StatusCode < 300 || resp.StatusCode > 399 || idx == -1 {
		return "", fmt.Errorf("could not resolve latest release (HTTP %d)", resp.StatusCode)
	}
	tag := strings.TrimSpace(loc[idx+len("/tag/"):])
	if tag == "" {
		return "", errors.New("latest release redirect had no tag")
	}
	return tag, nil
}

// UpToDate reports whether currentVersion already matches tag. A "dev" build
// never counts as up to date.
func UpToDate(currentVersion, tag string) bool {
	cur := strings.TrimPrefix(strings.TrimSpace(currentVersion), "v")
	if cur == "" || cur == "dev" {
		return false
	}
	return cur == strings.TrimPrefix(tag, "v")
}

// assetName returns the release asset for this platform, or an error when no
// asset is published for it.
func assetName(tag string) (string, error) {
	if runtime.GOARCH != "amd64" {
		return "", fmt.Errorf("no release assets are published for %s/%s; build from source to upgrade", runtime.GOOS, runtime.GOARCH)
	}
	switch runtime.GOOS {
	case "linux", "darwin":
		return fmt.Sprintf("cvetodo-agent-%s-%s-amd64.tar.gz", tag, runtime.GOOS), nil
	case "windows":
		return fmt.Sprintf("cvetodo-agent-%s-windows-amd64.zip", tag), nil
	default:
		return "", fmt.Errorf("no release assets are published for %s/%s; build from source to upgrade", runtime.GOOS, runtime.GOARCH)
	}
}

// Upgrade replaces the current executable with the latest release.
// checkOnly reports what would happen without changing anything; force
// re-installs even when the version already matches.
func Upgrade(currentVersion string, checkOnly, force bool) error {
	tag, err := LatestTag()
	if err != nil {
		return err
	}
	fmt.Printf("Current version: %s\nLatest release:  %s\n", currentVersion, tag)

	if UpToDate(currentVersion, tag) && !force {
		fmt.Println("Already up to date.")
		return nil
	}
	if checkOnly {
		fmt.Println("Upgrade available. Run 'cvetodo-agent upgrade' to install it.")
		return nil
	}

	asset, err := assetName(tag)
	if err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating current executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	tmpDir, err := os.MkdirTemp("", "cvetodo-agent-upgrade-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	base := "https://github.com/" + repo + "/releases/download/" + tag + "/"

	fmt.Printf("Downloading %s ...\n", asset)
	archivePath := filepath.Join(tmpDir, asset)
	if err := download(base+asset, archivePath); err != nil {
		return err
	}
	sums, err := fetchString(base + "SHA256SUMS")
	if err != nil {
		return fmt.Errorf("downloading SHA256SUMS: %w", err)
	}
	if err := verifyChecksum(archivePath, asset, sums); err != nil {
		return err
	}
	fmt.Println("Checksum verified.")

	newBin := filepath.Join(tmpDir, "cvetodo-agent.new")
	if err := extractBinary(archivePath, newBin); err != nil {
		return err
	}

	// Stop the service (when installed and running) before swapping the
	// binary; restart it afterwards so the upgrade is invisible to the
	// scan schedule.
	wasRunning := false
	if status, err := svc.Status(); err == nil && status == "running" {
		wasRunning = true
		fmt.Println("Stopping service ...")
		if err := svc.Control("stop"); err != nil {
			return fmt.Errorf("stopping service before upgrade: %w", err)
		}
	}

	if err := replaceExecutable(exe, newBin); err != nil {
		if wasRunning {
			_ = svc.Control("start") // best effort: leave the old version running
		}
		return err
	}
	fmt.Printf("Installed %s to %s.\n", tag, exe)

	if wasRunning {
		fmt.Println("Starting service ...")
		if err := svc.Control("start"); err != nil {
			return fmt.Errorf("upgrade succeeded but the service failed to start: %w", err)
		}
	}

	fmt.Println("Upgrade complete.")
	return nil
}

// download fetches url to path.
func download(url, path string) error {
	body, err := fetch(url)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, body); err != nil {
		_ = f.Close()
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	return f.Close()
}

func fetch(url string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cvetodo-agent-updater")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}

func fetchString(url string) (string, error) {
	body, err := fetch(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// verifyChecksum checks path against the entry for name in SHA256SUMS content
// (lines of "<hex>  <filename>", as produced by sha256sum).
func verifyChecksum(path, name, sums string) error {
	want := ""
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			want = strings.ToLower(fields[0])
			break
		}
	}
	if want == "" {
		return fmt.Errorf("SHA256SUMS has no entry for %s", name)
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", name, got, want)
	}
	return nil
}

// extractBinary pulls the agent binary out of a release archive to dest.
func extractBinary(archivePath, dest string) error {
	if strings.HasSuffix(archivePath, ".zip") {
		return extractZip(archivePath, "cvetodo-agent.exe", dest)
	}
	return extractTarGz(archivePath, "cvetodo-agent", dest)
}

func extractTarGz(archivePath, name, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(hdr.Name) == name && hdr.Typeflag == tar.TypeReg {
			return writeFile(dest, tr, 0755)
		}
	}
	return fmt.Errorf("%s not found in archive", name)
}

func extractZip(archivePath, name, dest string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer func() { _ = zr.Close() }()
	for _, file := range zr.File {
		if filepath.Base(file.Name) == name {
			rc, err := file.Open()
			if err != nil {
				return err
			}
			defer func() { _ = rc.Close() }()
			return writeFile(dest, rc, 0755)
		}
	}
	return fmt.Errorf("%s not found in archive", name)
}

func writeFile(path string, r io.Reader, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// replaceExecutable swaps exe with newBin via rename-then-replace. Renaming
// the running executable works on Windows too (the file object stays open
// under its new name), which is what makes in-place self-upgrade possible.
// The previous binary is kept as <exe>.old when it cannot be removed (the
// usual case on Windows while the old process is still this one) and cleaned
// up on the next upgrade.
func replaceExecutable(exe, newBin string) error {
	oldPath := exe + ".old"
	_ = os.Remove(oldPath) // leftover from a previous upgrade

	if err := os.Rename(exe, oldPath); err != nil {
		return fmt.Errorf("preparing to replace %s (administrator/root privileges are required): %w", exe, err)
	}

	// Try a straight rename first; fall back to copy for cross-device temp
	// dirs (common when /tmp is tmpfs).
	if err := os.Rename(newBin, exe); err != nil {
		if copyErr := copyFile(newBin, exe, 0755); copyErr != nil {
			_ = os.Rename(oldPath, exe) // roll back
			return fmt.Errorf("installing new binary: %w", copyErr)
		}
	}

	// Best effort; fails on Windows while the old binary is the running
	// process, and the next upgrade removes it.
	_ = os.Remove(oldPath)
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	return writeFile(dst, in, mode)
}
