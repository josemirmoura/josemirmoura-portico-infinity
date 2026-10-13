package securefs

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"syscall"
)

func TestReadWriteAndTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := New([]string{root}, []string{root}, 1024)
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "hello.txt")
	if err := m.WriteFileAtomic(target, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	got, err := m.ReadFile(target)
	if err != nil || string(got) != "hello" {
		t.Fatalf("read got %q err=%v", string(got), err)
	}

	traversal := filepath.Join(root, "..", filepath.Base(outside), "secret")
	if _, err := m.ReadFile(traversal); err == nil {
		t.Fatal("expected traversal denial")
	}
}

func TestSymlinkEscapeDenied(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("classified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	m, err := New([]string{root}, []string{root}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReadFile(filepath.Join(root, "escape")); err == nil {
		t.Fatal("expected os.Root to reject symlink escape")
	}
}

func TestConfiguredSymlinkRootRejected(t *testing.T) {
	outside := t.TempDir()
	base := t.TempDir()
	link := filepath.Join(base, "authorized")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := New([]string{link}, []string{link}, 1024); err == nil {
		t.Fatal("configured authorized root symlink was accepted")
	}
}

func TestConfiguredRootWithSymlinkAncestorRejected(t *testing.T) {
	outside := t.TempDir()
	base := t.TempDir()
	link := filepath.Join(base, "linked-parent")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	configured := filepath.Join(link, "child")
	if _, err := New([]string{configured}, []string{configured}, 1024); err == nil {
		t.Fatal("configured root below a symlink ancestor was accepted")
	}
}

func TestPrefixConfusionDenied(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "app")
	confusing := filepath.Join(base, "application")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(confusing, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(confusing, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ := New([]string{root}, []string{root}, 1024)
	if _, err := m.ReadFile(filepath.Join(confusing, "secret")); err == nil {
		t.Fatal("prefix-confused path must be denied")
	}
}


func TestMkdirAllCanCreateConfiguredRoot(t *testing.T) {
	base := t.TempDir()
	targetRoot := filepath.Join(base, "new-root")
	m, err := New([]string{targetRoot}, []string{targetRoot}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.MkdirAll(targetRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(targetRoot)
	if err != nil || !info.IsDir() {
		t.Fatalf("configured root was not created: info=%v err=%v", info, err)
	}
	if err := m.WriteFileAtomic(filepath.Join(targetRoot, "index.html"), []byte("<3")); err != nil {
		t.Fatal(err)
	}
}

func TestMkdirAllRejectsOutsideAndSymlink(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "allowed")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	m, err := New([]string{root}, []string{root}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.MkdirAll(filepath.Join(base, "outside"), 0o750); err == nil {
		t.Fatal("outside directory creation was allowed")
	}

	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := m.MkdirAll(filepath.Join(root, "link", "child"), 0o750); err == nil {
		t.Fatal("symlink directory component was followed")
	}
}


func TestCompleteFilesystemToolbox(t *testing.T) {
	root := t.TempDir()
	m, err := New([]string{root}, []string{root}, 4096)
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(root, "a", "b")
	if err := m.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "file.txt")
	if err := m.WriteFileAtomic(file, []byte("alpha beta gamma")); err != nil {
		t.Fatal(err)
	}

	entries, err := m.List(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "file.txt" {
		t.Fatalf("unexpected list: %+v", entries)
	}

	st, err := m.Stat(file, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != int64(len("alpha beta gamma")) || st.IsDir {
		t.Fatalf("unexpected stat: %+v", st)
	}

	hash1, err := m.Hash(file)
	if err != nil || len(hash1) != 64 {
		t.Fatalf("hash=%q err=%v", hash1, err)
	}

	hash2, err := m.Patch(file, "beta", "BETA", hash1)
	if err != nil || hash2 == hash1 {
		t.Fatalf("patch hash=%q err=%v", hash2, err)
	}
	data, _ := m.ReadFile(file)
	if string(data) != "alpha BETA gamma" {
		t.Fatalf("patch result=%q", data)
	}

	copyPath := filepath.Join(dir, "copy.txt")
	if err := m.CopyFile(file, copyPath); err != nil {
		t.Fatal(err)
	}
	movePath := filepath.Join(dir, "moved.txt")
	if err := m.Move(copyPath, movePath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Fatalf("copy source still exists after move: %v", err)
	}

	if err := m.Chmod(movePath, 0o777); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(movePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o777 {
		t.Fatalf("chmod got %o", info.Mode().Perm())
	}

	if err := m.Remove(movePath, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Remove(filepath.Join(root, "a"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "a")); !os.IsNotExist(err) {
		t.Fatalf("recursive removal failed: %v", err)
	}
}

func TestPatchPreconditionAndAmbiguity(t *testing.T) {
	root := t.TempDir()
	m, _ := New([]string{root}, []string{root}, 4096)
	file := filepath.Join(root, "x.txt")
	_ = m.WriteFileAtomic(file, []byte("same same"))
	if _, err := m.Patch(file, "same", "new", ""); err == nil {
		t.Fatal("ambiguous patch was allowed")
	}
	if _, err := m.Patch(file, "same same", "new", strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong sha precondition was allowed")
	}
}

func TestRecursiveRemoveDoesNotFollowSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	m, _ := New([]string{root}, []string{root}, 4096)
	tree := filepath.Join(root, "tree")
	if err := os.MkdirAll(tree, 0o750); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tree, "outside-link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := m.Remove(tree, true); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(secret); err != nil || string(got) != "keep" {
		t.Fatalf("recursive delete escaped through symlink: got=%q err=%v", got, err)
	}
}


func TestHostRootMappingPreservesCanonicalPaths(t *testing.T) {
	host := t.TempDir()
	canonicalRoot := "/opt/project"
	physicalRoot := filepath.Join(host, "opt", "project")
	if err := os.MkdirAll(physicalRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	m, err := NewWithHostRoot([]string{canonicalRoot}, []string{canonicalRoot}, 4096, host)
	if err != nil {
		t.Fatal(err)
	}
	target := "/opt/project/hello.txt"
	if err := m.WriteFileAtomic(target, []byte("host-root")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(physicalRoot, "hello.txt"))
	if err != nil || string(got) != "host-root" {
		t.Fatalf("physical file=%q err=%v", got, err)
	}
	entries, err := m.List(canonicalRoot, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Path != "/opt/project/hello.txt" {
		t.Fatalf("canonical path leaked host prefix: %+v", entries)
	}
}


func FuzzSelectRootNeverEscapes(f *testing.F) {
	root := filepath.Clean("/srv/allowed")
	for _, seed := range []string{"/srv/allowed/file", "/srv/allowed/../etc/passwd", "/srv/allowed2/x", "/etc/shadow", "", "../../etc"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, target string) {
		selected, _, err := selectRoot([]string{root}, target)
		if err != nil {
			return
		}
		if selected != root {
			t.Fatalf("unexpected selected root %q for %q", selected, target)
		}
		abs, err := filepath.Abs(target)
		if err != nil { return }
		rel, err := filepath.Rel(root, filepath.Clean(abs))
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			t.Fatalf("authorized target escaped root: target=%q rel=%q err=%v", target, rel, err)
		}
	})
}


func TestHardlinkRemovalDoesNotAffectOutsideName(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "original.txt")
	if err := os.WriteFile(outsideFile, []byte("keep-me"), 0o600); err != nil {
		t.Fatal(err)
	}
	insideLink := filepath.Join(root, "inside-link.txt")
	if err := os.Link(outsideFile, insideLink); err != nil {
		t.Skipf("hardlink unavailable on this filesystem: %v", err)
	}

	m, err := New([]string{root}, []string{root}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Remove(insideLink, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(insideLink); !os.IsNotExist(err) {
		t.Fatalf("inside hardlink still exists after removal: %v", err)
	}
	got, err := os.ReadFile(outsideFile)
	if err != nil || string(got) != "keep-me" {
		t.Fatalf("outside hardlink name/content was affected: got=%q err=%v", got, err)
	}
}

func TestMoveCannotFollowSymlinkDirectoryOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	src := filepath.Join(root, "src.txt")
	if err := os.WriteFile(src, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "escape-dir")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	m, err := New([]string{root}, []string{root}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Move(src, filepath.Join(linkDir, "escaped.txt")); err == nil {
		t.Fatal("move unexpectedly followed a symlink directory outside the authorized root")
	}
	if _, err := os.Stat(filepath.Join(outside, "escaped.txt")); !os.IsNotExist(err) {
		t.Fatalf("move created an outside file through symlink: %v", err)
	}
}

func TestConcurrentSymlinkSwapNeverReadsOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("outside-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "victim.txt")
	regular := filepath.Join(root, "regular.tmp")
	link := filepath.Join(root, "link.tmp")
	if err := os.WriteFile(target, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	m, err := New([]string{root}, []string{root}, 4096)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Remove(target)
			_ = os.Rename(link, target)
			_ = os.Rename(target, link)
			_ = os.Rename(regular, target)
			_ = os.Rename(target, regular)
		}
	}()

	for i := 0; i < 4000; i++ {
		data, err := m.ReadFile(target)
		if err != nil {
			continue
		}
		if string(data) == "outside-secret" {
			close(stop)
			wg.Wait()
			t.Fatal("concurrent symlink swap escaped the authorized root")
		}
		if string(data) != "inside" {
			close(stop)
			wg.Wait()
			t.Fatalf("unexpected content during race: %q", data)
		}
	}
	close(stop)
	wg.Wait()

	got, err := os.ReadFile(outsideFile)
	if err != nil || string(got) != "outside-secret" {
		t.Fatalf("outside target changed during race: got=%q err=%v", got, err)
	}
}

// TestAtomicWriteHostOwner mirrors the E2E operator case. A Broker running
// as root must not leave a newly created file root-owned inside an authorized
// directory owned by an unprivileged operator.
func TestAtomicWriteHostOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required to simulate broker writing into another user's directory")
	}
	root := t.TempDir()
	const operatorUID, operatorGID = 12345, 12346
	if err := os.Chown(root, operatorUID, operatorGID); err != nil { t.Fatal(err) }
	m, err := New([]string{root}, []string{root}, 1024)
	if err != nil { t.Fatal(err) }
	file := filepath.Join(root, "operator.txt")
	for _, content := range []string{"created", "overwritten"} {
		if err := m.WriteFileAtomic(file, []byte(content)); err != nil { t.Fatal(err) }
		info, err := os.Lstat(file)
		if err != nil { t.Fatal(err) }
		meta, ok := info.Sys().(*syscall.Stat_t)
		if !ok { t.Fatal("stat_t unavailable") }
		if meta.Uid != operatorUID || meta.Gid != operatorGID {
			t.Fatalf("file owner %d:%d, expected operator %d:%d",
				meta.Uid, meta.Gid, operatorUID, operatorGID)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("file mode %o should be limited to owner", info.Mode().Perm())
		}
	}
	data, err := os.ReadFile(file)
	if err != nil || string(data) != "overwritten" {
		t.Fatalf("final content %q err=%v", data, err)
	}
}

func TestAtomicWritePreservesExistingDifferentOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for distinct existing file and parent owner")
	}
	root := t.TempDir()
	const dirUID, dirGID = 12345, 12346
	const fileUID, fileGID = 12347, 12348
	if err := os.Chown(root, dirUID, dirGID); err != nil { t.Fatal(err) }
	file := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(file, []byte("before"), 0o600); err != nil { t.Fatal(err) }
	if err := os.Chown(file, fileUID, fileGID); err != nil { t.Fatal(err) }
	m, err := New([]string{root}, []string{root}, 1024)
	if err != nil { t.Fatal(err) }
	if err := m.WriteFileAtomic(file, []byte("after")); err != nil { t.Fatal(err) }
	info, err := os.Lstat(file)
	if err != nil { t.Fatal(err) }
	meta, ok := info.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != fileUID || meta.Gid != fileGID {
		t.Fatalf("original file owner was not preserved: %+v", info.Sys())
	}
}

func TestAtomicWriteSymlinkTargetRefusedWithoutReplacement(t *testing.T) {
	root := t.TempDir()
	m, err := New([]string{root}, []string{root}, 1024)
	if err != nil { t.Fatal(err) }
	target := filepath.Join(root, "existing.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil { t.Fatal(err) }
	link := filepath.Join(root, "alias.txt")
	if err := os.Symlink(target, link); err != nil { t.Skip(err) }
	if err := m.WriteFileAtomic(link, []byte("new")); err == nil {
		t.Fatal("atomic write must reject symlink instead of silently replacing it")
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink was modified or removed: %v", err)
	}
	b, err := os.ReadFile(target)
	if err != nil || string(b) != "original" {
		t.Fatalf("referent changed: %q err=%v", b, err)
	}
}

func TestAtomicWriteOwnerPreservesForeignRootBoundary(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	m, err := New([]string{root}, []string{root}, 1024)
	if err != nil { t.Fatal(err) }
	target := filepath.Join(outside, "escape.txt")
	if err := m.WriteFileAtomic(target, []byte("out")); err == nil {
		t.Fatal("writes outside root must remain forbidden")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("out-of-scope file created: %v", err)
	}
}


func TestAuthorizedRootSwapAfterNewFailsClosed(t *testing.T) {
	base := t.TempDir()
	granted := filepath.Join(base, "granted")
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(granted, 0o750); err != nil { t.Fatal(err) }
	if err := os.Mkdir(outside, 0o750); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("private"), 0o600); err != nil { t.Fatal(err) }

	m, err := New([]string{granted}, []string{granted}, 1024)
	if err != nil { t.Fatal(err) }
	if err := os.Rename(granted, granted+"-parked"); err != nil { t.Fatal(err) }
	if err := os.Symlink(outside, granted); err != nil { t.Fatal(err) }

	if data, err := m.ReadFile(filepath.Join(granted, "secret")); err == nil {
		t.Fatalf("root swap revealed unauthorized bytes: %q", data)
	}
	if err := m.WriteFileAtomic(filepath.Join(granted, "new.txt"), []byte("unauthorized")); err == nil {
		t.Fatal("root swap permitted write into outside directory")
	}
	if _, err := m.List(granted, 10); err == nil {
		t.Fatal("root swap permitted directory listing")
	}
	if err := m.MkdirAll(filepath.Join(granted, "subdir"), 0o750); err == nil {
		t.Fatal("root swap permitted mkdir through a replaced root")
	}
	if _, err := os.Lstat(filepath.Join(outside, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("outside target changed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "subdir")); !os.IsNotExist(err) {
		t.Fatalf("outside directory created: %v", err)
	}
	if err := os.Remove(granted); err != nil { t.Fatal(err) }
	if err := os.Rename(granted+"-parked", granted); err != nil { t.Fatal(err) }
	if err := m.WriteFileAtomic(filepath.Join(granted, "restored.txt"), []byte("authorized")); err != nil {
		t.Fatalf("restoring original root inode should restore access: %v", err)
	}
}

func TestAuthorizedAncestorSwapAfterNewFailsClosed(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	granted := filepath.Join(parent, "grant")
	outsideParent := filepath.Join(base, "outside")
	outsideGrant := filepath.Join(outsideParent, "grant")
	for _, dir := range []string{parent, granted, outsideParent, outsideGrant} {
		if err := os.Mkdir(dir, 0o750); err != nil { t.Fatal(err) }
	}
	if err := os.WriteFile(filepath.Join(outsideGrant, "secret"), []byte("outside"), 0o600); err != nil { t.Fatal(err) }
	m, err := New([]string{granted}, []string{granted}, 1024)
	if err != nil { t.Fatal(err) }
	if err := os.Rename(parent, parent+"-parked"); err != nil { t.Fatal(err) }
	if err := os.Symlink(outsideParent, parent); err != nil { t.Fatal(err) }
	if data, err := m.ReadFile(filepath.Join(granted, "secret")); err == nil {
		t.Fatalf("ancestor swap disclosed outside data: %q", data)
	}
	if err := m.WriteFileAtomic(filepath.Join(granted, "attack"), []byte("attack")); err == nil {
		t.Fatal("ancestor swap permitted writing to unauthorised subtree")
	}
	if _, err := os.Stat(filepath.Join(outsideGrant, "attack")); !os.IsNotExist(err) {
		t.Fatalf("ancestor swap wrote outside: %v", err)
	}
}

func TestPinnedMissingRootCanBeCreatedThenUsed(t *testing.T) {
	base := t.TempDir()
	granted := filepath.Join(base, "new-tenant", "project")
	m, err := New([]string{granted}, []string{granted}, 1024)
	if err != nil { t.Fatal(err) }
	if err := m.MkdirAll(granted, 0o750); err != nil { t.Fatalf("creation of missing root failed: %v", err) }
	target := filepath.Join(granted, "verified.txt")
	if err := m.WriteFileAtomic(target, []byte("yes")); err != nil { t.Fatalf("newly pinned root cannot write: %v", err) }
	out, err := m.ReadFile(target)
	if err != nil || string(out) != "yes" { t.Fatalf("newly pinned root cannot read: %q, %v", out, err) }
}

func TestDirectoryHostOwner(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("requires root Broker analog") }
	root := t.TempDir()
	const operatorUID, operatorGID = 12345, 12346
	if err := os.Chown(root, operatorUID, operatorGID); err != nil { t.Fatal(err) }
	m, err := New([]string{root}, []string{root}, 1024)
	if err != nil { t.Fatal(err) }
	deep := filepath.Join(root, "nested", "deep")
	if err := m.MkdirAll(deep, 0o750); err != nil { t.Fatal(err) }
	for _, path := range []string{filepath.Join(root, "nested"), deep} {
		info, err := os.Lstat(path)
		if err != nil { t.Fatal(err) }
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != operatorUID || stat.Gid != operatorGID {
			t.Fatalf("directory %s owner not inherited from authorized parent: %+v", path, info.Sys())
		}
	}
}

func TestCopyFileHostOwner(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("requires root Broker analog") }
	root := t.TempDir()
	const operatorUID, operatorGID = 12345, 12346
	const existingUID, existingGID = 12347, 12348
	if err := os.Chown(root, operatorUID, operatorGID); err != nil { t.Fatal(err) }
	src := filepath.Join(root, "source.txt")
	if err := os.WriteFile(src, []byte("data"), 0o600); err != nil { t.Fatal(err) }
	m, err := New([]string{root}, []string{root}, 1024)
	if err != nil { t.Fatal(err) }
	for _, item := range []struct{ file string; uid, gid uint32 }{
		{filepath.Join(root, "new.txt"), operatorUID, operatorGID},
		{filepath.Join(root, "existing.txt"), existingUID, existingGID},
	} {
		if item.uid == existingUID {
			if err := os.WriteFile(item.file, []byte("old"), 0o600); err != nil { t.Fatal(err) }
			if err := os.Chown(item.file, existingUID, existingGID); err != nil { t.Fatal(err) }
		}
		if err := m.CopyFile(src, item.file); err != nil { t.Fatal(err) }
		info, err := os.Lstat(item.file)
		if err != nil { t.Fatal(err) }
		meta, ok := info.Sys().(*syscall.Stat_t)
		if !ok || meta.Uid != item.uid || meta.Gid != item.gid {
			t.Fatalf("copy %s owner %v, expected %d:%d", item.file, info.Sys(), item.uid, item.gid)
		}
	}
}

func TestMoveAcrossRootsHostOwner(t *testing.T) {
	if os.Geteuid() != 0 { t.Skip("requires root Broker analog") }
	base := t.TempDir()
	srcRoot := filepath.Join(base, "source")
	dstRoot := filepath.Join(base, "dest")
	for _, name := range []string{srcRoot, dstRoot} {
		if err := os.Mkdir(name, 0o750); err != nil { t.Fatal(err) }
	}
	const operatorUID, operatorGID = 12345, 12346
	if err := os.Chown(dstRoot, operatorUID, operatorGID); err != nil { t.Fatal(err) }
	src := filepath.Join(srcRoot, "payload")
	dst := filepath.Join(dstRoot, "payload")
	if err := os.WriteFile(src, []byte("payload"), 0o600); err != nil { t.Fatal(err) }
	m, err := New([]string{srcRoot, dstRoot}, []string{srcRoot, dstRoot}, 1024)
	if err != nil { t.Fatal(err) }
	if err := m.Move(src, dst); err != nil { t.Fatal(err) }
	info, err := os.Lstat(dst)
	if err != nil { t.Fatal(err) }
	meta, ok := info.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != operatorUID || meta.Gid != operatorGID {
		t.Fatalf("cross-root move owner should derive from destination: %+v", info.Sys())
	}
	if _, err := os.Lstat(src); !os.IsNotExist(err) {
		t.Fatalf("source must be absent after move: %v", err)
	}
}
