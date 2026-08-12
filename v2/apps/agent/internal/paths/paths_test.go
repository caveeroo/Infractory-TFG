package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootConfinesPathsAndWritesAtomically(t *testing.T) {
	r, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Path("..", "escape"); err == nil {
		t.Fatal("expected traversal rejection")
	}
	if _, err := r.Path("/etc/passwd"); err == nil {
		t.Fatal("expected absolute component rejection")
	}
	if err := r.AtomicWrite(0600, []byte("secret"), "credentials", "device-token"); err != nil {
		t.Fatal(err)
	}
	p, _ := r.Path("credentials", "device-token")
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "secret" {
		t.Fatalf("read: %q %v", b, err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", st.Mode().Perm())
	}
	if filepath.Dir(p) == "/etc" {
		t.Fatal("escaped root")
	}
}

func TestAtomicWriteRejectsSymlinkedParentEscape(t *testing.T) {
	state, outside := t.TempDir(), t.TempDir()
	r, _ := New(state)
	if err := os.Symlink(outside, filepath.Join(state, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := r.AtomicWrite(0600, []byte("escape"), "linked", "nested", "file"); err == nil {
		t.Fatal("expected symlink escape rejection")
	}
	if _, err := os.Stat(filepath.Join(outside, "file")); !os.IsNotExist(err) {
		t.Fatalf("outside file created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "nested")); !os.IsNotExist(err) {
		t.Fatalf("outside directory created before rejection: %v", err)
	}
}
