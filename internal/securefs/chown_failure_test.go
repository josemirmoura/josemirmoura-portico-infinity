package securefs

import (
    "errors"
    "os"
    "path/filepath"
    "strings"
    "syscall"
    "testing"
)

// An empty directory is intentionally retained on fchown failure.
// Cleanup is operator-supervised, never an unlink by name in MkdirAll.
func TestMkdirAllChownFailureResidueAndControlledRetry(t *testing.T) {
    if os.Geteuid() != 0 { t.Skip("privileged Broker analog needs root") }
    root := t.TempDir()
    const operatorUID, operatorGID = 12345, 12346
    if err := os.Chown(root, operatorUID, operatorGID); err != nil { t.Fatal(err) }
    manager, err := New([]string{root}, []string{root}, 1024)
    if err != nil { t.Fatal(err) }
    target := filepath.Join(root, "new-dir")
    manager.mkdirChown = func(_ *os.File, _, _ int) error { return syscall.EPERM }
    err = manager.MkdirAll(target, 0o700)
    if err == nil || !strings.Contains(err.Error(), "MANUAL RECOVERY") || !strings.Contains(err.Error(), target) {
        t.Fatalf("expected explicit recovery instructions for failed Chown, got: %v", err)
    }
    info, err := os.Lstat(target)
    if err != nil || !info.IsDir() { t.Fatalf("partial directory must remain observable: %v", err) }
    meta := info.Sys().(*syscall.Stat_t)
    if meta.Uid != 0 { t.Fatalf("expected root-owned partial directory, got uid=%d", meta.Uid) }
    manager.mkdirChown = nil
    // The operator verifies the path and removes the empty fixture before retrying.
    if err := os.Remove(target); err != nil { t.Fatal(err) }
    if err := manager.MkdirAll(target, 0o700); err != nil { t.Fatalf("controlled retry failed: %v", err) }
    info, err = os.Lstat(target)
    if err != nil { t.Fatal(err) }
    meta = info.Sys().(*syscall.Stat_t)
    if meta.Uid != operatorUID || meta.Gid != operatorGID {
        t.Fatalf("retried directory owner %d:%d, expected %d:%d", meta.Uid, meta.Gid, operatorUID, operatorGID)
    }
}

// A simultaneous process swaps the just-created directory for another
// (potentially foreign) empty directory while Chown is failing. The Broker
// must not remove either path, nor report that a rollback completed.
func TestMkdirAllChownFailureSwappedDirectoryNeverUnlinked(t *testing.T) {
    if os.Geteuid() != 0 { t.Skip("privileged Broker analog needs root") }
    root := t.TempDir()
    const operatorUID, operatorGID = 12345, 12346
    if err := os.Chown(root, operatorUID, operatorGID); err != nil { t.Fatal(err) }
    manager, err := New([]string{root}, []string{root}, 1024)
    if err != nil { t.Fatal(err) }
    target := filepath.Join(root, "new-dir")
    moved := filepath.Join(root, "original-moved")
    replacement := filepath.Join(root, "another-process-owned")
    if err := os.Mkdir(replacement, 0o700); err != nil { t.Fatal(err) }
    manager.mkdirChown = func(_ *os.File, _, _ int) error {
        if err := os.Rename(target, moved); err != nil { return err }
        if err := os.Rename(replacement, target); err != nil { return err }
        return syscall.EPERM
    }
    err = manager.MkdirAll(target, 0o700)
    if err == nil || !strings.Contains(err.Error(), "MANUAL RECOVERY") {
        t.Fatalf("unexpected result after concurrent name swap: %v", err)
    }
    for _, path := range []string{target, moved} {
        info, err := os.Lstat(path)
        if err != nil || !info.IsDir() { t.Fatalf("path must survive failed Chown, %q: %v", path, err) }
    }
}

func TestMkdirAllChownFailureNonemptyResidueRequiresRecovery(t *testing.T) {
    if os.Geteuid() != 0 { t.Skip("privileged Broker analog needs root") }
    root := t.TempDir()
    outside := t.TempDir()
    const operatorUID, operatorGID = 12345, 12346
    if err := os.Chown(root, operatorUID, operatorGID); err != nil { t.Fatal(err) }
    manager, err := New([]string{root}, []string{root}, 1024)
    if err != nil { t.Fatal(err) }
    target := filepath.Join(root, "partial")
    outsideFile := filepath.Join(outside, "must-stay")
    if err := os.WriteFile(outsideFile, []byte("foreign"), 0o600); err != nil { t.Fatal(err) }
    manager.mkdirChown = func(_ *os.File, _, _ int) error {
        // Simulate a process placing a file into the newly created directory
        // before the chown syscall returns. The directory is no longer empty.
        if err := os.WriteFile(filepath.Join(target, "content"), []byte("keep"), 0o600); err != nil { return err }
        return syscall.EPERM
    }
    err = manager.MkdirAll(target, 0o700)
    if err == nil || !strings.Contains(err.Error(), "MANUAL RECOVERY") || !strings.Contains(err.Error(), target) {
        t.Fatalf("expected visible recoverable residue path, got: %v", err)
    }
    info, err := os.Lstat(target)
    if err != nil { t.Fatalf("residue was not documented or retained: %v", err) }
    if !info.IsDir() { t.Fatal("residual directory is not a directory") }
    data, err := os.ReadFile(filepath.Join(target, "content"))
    if err != nil || string(data) != "keep" { t.Fatalf("residual nested data lost: %q, %v", data, err) }
    foreign, err := os.ReadFile(outsideFile)
    if err != nil || string(foreign) != "foreign" { t.Fatalf("unrelated file changed: %q, %v", foreign, err) }
}

func TestMkdirAllChownFailureCannotCreateOutOfScope(t *testing.T) {
    root := t.TempDir()
    outside := t.TempDir()
    manager, err := New([]string{root}, []string{root}, 1024)
    if err != nil { t.Fatal(err) }
    manager.mkdirChown = func(_ *os.File, _, _ int) error { return syscall.EPERM }
    target := filepath.Join(outside, "not-allowed")
    if err := manager.MkdirAll(target, 0o700); err == nil { t.Fatal("out-of-scope MkdirAll unexpectedly accepted") }
    if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) { t.Fatalf("out-of-scope target created: %v", err) }
}
