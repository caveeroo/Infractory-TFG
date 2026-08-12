package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Root struct{ path string }

func New(path string) (Root, error) {
	if !filepath.IsAbs(path) {
		return Root{}, errors.New("state root must be absolute")
	}
	return Root{path: filepath.Clean(path)}, nil
}

func (r Root) Path(parts ...string) (string, error) {
	for _, part := range parts {
		if filepath.IsAbs(part) {
			return "", errors.New("absolute path component is forbidden")
		}
	}
	joined := filepath.Join(append([]string{r.path}, parts...)...)
	clean := filepath.Clean(joined)
	rel, err := filepath.Rel(r.path, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errors.New("path escapes state root")
	}
	return clean, nil
}

func (r Root) Ensure() error {
	if err := os.MkdirAll(r.path, 0700); err != nil {
		return fmt.Errorf("create state root: %w", err)
	}
	info, err := os.Lstat(r.path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state root must be a real directory, not a symlink")
	}
	return os.Chmod(r.path, 0700)
}

func (r Root) Resolve(parts ...string) (string, error) {
	p, err := r.Path(parts...)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if err := r.verifyResolved(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func (r Root) AtomicWrite(mode os.FileMode, data []byte, parts ...string) error {
	dst, err := r.Path(parts...)
	if err != nil {
		return err
	}
	if err := r.ensureDirectory(filepath.Dir(dst)); err != nil {
		return err
	}
	if err := r.verifyResolved(filepath.Dir(dst)); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(dst), ".infractory-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(dst))
	if err == nil {
		defer d.Close()
		_ = d.Sync()
	}
	return nil
}

func (r Root) ensureDirectory(path string) error {
	rel, err := filepath.Rel(r.path, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("directory escapes state root")
	}
	current := r.path
	for _, component := range strings.Split(rel, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, lstatErr := os.Lstat(current)
		if errors.Is(lstatErr, os.ErrNotExist) {
			if err := os.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			continue
		}
		if lstatErr != nil {
			return lstatErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("state path contains a symlink or non-directory")
		}
	}
	return nil
}

func (r Root) verifyResolved(path string) error {
	resolvedRoot, err := filepath.EvalSymlinks(r.path)
	if err != nil {
		return err
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errors.New("resolved path escapes state root")
	}
	return nil
}

func (r Root) Remove(parts ...string) error {
	p, err := r.Path(parts...)
	if err != nil {
		return err
	}
	if p == r.path {
		return errors.New("refusing to remove state root")
	}
	if err := r.verifyResolved(filepath.Dir(p)); err != nil {
		return err
	}
	return os.RemoveAll(p)
}
