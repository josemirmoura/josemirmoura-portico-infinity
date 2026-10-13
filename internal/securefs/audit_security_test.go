package securefs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAuthorizedRootSwapToSymlinkNeverEscapes(t *testing.T) {
	base := t.TempDir()
	allowed, outside := filepath.Join(base, "allowed"), filepath.Join(base, "outside")
	if err := os.Mkdir(allowed, 0o700); err != nil { t.Fatal(err) }
	if err := os.Mkdir(outside, 0o700); err != nil { t.Fatal(err) }
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("outside-secret"), 0o600); err != nil { t.Fatal(err) }
	m, err := New([]string{allowed}, []string{allowed}, 1024)
	if err != nil { t.Fatal(err) }
	if err := os.Rename(allowed, allowed+"-old"); err != nil { t.Fatal(err) }
	if err := os.Symlink(outside, allowed); err != nil { t.Skipf("symlink unavailable: %v", err) }
	if data, err := m.ReadFile(filepath.Join(allowed, "secret")); err == nil {
		t.Fatalf("read redirected root and leaked %q", data)
	}
	if err := m.WriteFileAtomic(filepath.Join(allowed, "created"), []byte("escape")); err == nil {
		t.Fatal("write redirected root must fail")
	}
	if _, err := os.Lstat(filepath.Join(outside, "created")); !os.IsNotExist(err) {
		t.Fatalf("write escaped to foreign directory: %v", err)
	}
	if _, err := m.Stat(filepath.Join(allowed, "secret"), false); err == nil {
		t.Fatal("stat redirected root must fail")
	}
	if _, err := m.List(allowed, 5); err == nil {
		t.Fatal("list redirected root must fail")
	}
	if _, err := m.Hash(filepath.Join(allowed, "secret")); err == nil {
		t.Fatal("hash redirected root must fail")
	}
}

func TestAuthorizedAncestorSwapToSymlinkNeverEscapes(t *testing.T) {
	base := t.TempDir()
	parent, outer := filepath.Join(base, "original-parent"), filepath.Join(base, "external-parent")
	allowed := filepath.Join(parent, "authorized")
	if err := os.MkdirAll(allowed, 0o700); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(filepath.Join(outer, "authorized"), 0o700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(outer, "authorized", "secret"), []byte("foreign"), 0o600); err != nil { t.Fatal(err) }
	m, err := New([]string{allowed}, []string{allowed}, 1024)
	if err != nil { t.Fatal(err) }
	if err := os.Rename(parent, parent+"-old"); err != nil { t.Fatal(err) }
	if err := os.Symlink(outer, parent); err != nil { t.Skipf("symlink unavailable: %v", err) }
	if data, err := m.ReadFile(filepath.Join(allowed, "secret")); err == nil {
		t.Fatalf("ancestor symlink leaked %q", data)
	}
	if err := m.MkdirAll(filepath.Join(allowed, "created"), 0o700); err == nil {
		t.Fatal("mkdir redirected ancestor must fail")
	}
	if _, err := os.Lstat(filepath.Join(outer, "authorized", "created")); !os.IsNotExist(err) {
		t.Fatalf("mkdir created foreign directory: %v", err)
	}
}

// The root path is swapped in parallel with opens, not only after New.
// Successful reads may return data from the original directory or fail;
// they must never return bytes redirected through the external symlink.
func TestConcurrentAuthorizedRootSwapNeverLeaks(t *testing.T) {
	base := t.TempDir()
	allowed := filepath.Join(base, "authorized")
	outside := filepath.Join(base, "external")
	if err := os.Mkdir(allowed, 0o700); err != nil { t.Fatal(err) }
	if err := os.Mkdir(outside, 0o700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(allowed, "secret"), []byte("allowed"), 0o600); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside-data"), 0o600); err != nil { t.Fatal(err) }
	m, err := New([]string{allowed}, []string{allowed}, 1024)
	if err != nil { t.Fatal(err) }
	done := make(chan error, 1)
	go func() {
		moved := allowed + "-moved"
		for i := 0; i < 250; i++ {
			if err := os.Rename(allowed, moved); err != nil { done <- err; return }
			if err := os.Symlink(outside, allowed); err != nil { done <- err; return }
			if err := os.Remove(allowed); err != nil { done <- err; return }
			if err := os.Rename(moved, allowed); err != nil { done <- err; return }
		}
		done <- nil
	}()
	for i := 0; i < 2500; i++ {
		data, err := m.ReadFile(filepath.Join(allowed, "secret"))
		if err == nil && string(data) != "allowed" {
			t.Errorf("redirected authorized root leaked foreign data: %q", data)
			break
		}
	}
	if swapErr := <-done; swapErr != nil { t.Fatalf("adversarial swap failed: %v", swapErr) }
}

func TestOwnerNewDirectoryAndCopyAcrossRoots(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("requires root Broker analog in disposable CI") }
	base := t.TempDir()
	src, dst := filepath.Join(base, "src"), filepath.Join(base, "dst")
	if err := os.Mkdir(src, 0o700); err != nil { t.Fatal(err) }
	if err := os.Mkdir(dst, 0o700); err != nil { t.Fatal(err) }
	const operatorUID, operatorGID = 12345, 12346
	if err := os.Chown(dst, operatorUID, operatorGID); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(src, "seed"), []byte("data"), 0o600); err != nil { t.Fatal(err) }
	m, err := New([]string{src, dst}, []string{dst}, 1024)
	if err != nil { t.Fatal(err) }
	newDir := filepath.Join(dst, "child", "grandchild")
	if err := m.MkdirAll(newDir, 0o700); err != nil { t.Fatal(err) }
	newFile := filepath.Join(newDir, "copied")
	if err := m.CopyFile(filepath.Join(src, "seed"), newFile); err != nil { t.Fatal(err) }
	for _, path := range []string{filepath.Join(dst, "child"), newDir, newFile} {
		info, err := os.Lstat(path)
		if err != nil { t.Fatal(err) }
		id, ok := info.Sys().(*syscall.Stat_t)
		if !ok || id.Uid != operatorUID || id.Gid != operatorGID {
			t.Fatalf("%s UID:GID = %v, expected %d:%d", path, info.Sys(), operatorUID, operatorGID)
		}
	}
	// A move between distinct authorized roots delegates to CopyFile and
	// must inherit the destination owner's UID/GID rather than root's.
	mBoth, err := New([]string{src, dst}, []string{src, dst}, 1024)
	if err != nil { t.Fatal(err) }
	if err := mBoth.Move(filepath.Join(src, "seed"), filepath.Join(dst, "moved")); err != nil { t.Fatal(err) }
	info, err := os.Lstat(filepath.Join(dst, "moved"))
	if err != nil { t.Fatal(err) }
	id := info.Sys().(*syscall.Stat_t)
	if id.Uid != operatorUID || id.Gid != operatorGID {
		t.Fatalf("moved file UID:GID was not preserved: %+v", id)
	}
}
