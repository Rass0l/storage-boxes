package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestExtractArchiveLandsAtTarget exercises the extractor against
// archives of both shapes the operator may encounter:
//
//   - content-style (new): `tar -C root -czf out.tgz .`
//     — no named top-level directory. This is what backup.sh emits
//     going forward.
//   - legacy named-top-dir: `tar -C dirname(root) -czf out.tgz basename(root)`
//     — every archive entry lives under a single top-level directory
//     whose basename matches the source machine's BOX_STORAGE_ROOT /
//     SHARE_STAGE_ROOT name. Pre-patch backup.sh emitted this shape.
//
// In both cases the extractor must land the archive contents at the
// target directory, not at `target/<archive-topname>/...`, regardless
// of whether the target basename matches the archived one. That is
// the promise restore.sh relies on.
func TestExtractArchiveLandsAtTarget(t *testing.T) {
	extractor := locate(t, filepath.Join("scripts", "_extract-archive.sh"))

	run := func(name string, archiveLayout func(root string) (string, func())) {
		t.Run(name, func(t *testing.T) {
			// Source tree: two boxes with one blob each.
			src := t.TempDir()
			mustWrite(t, filepath.Join(src, "box_a", "sk_1"), []byte("alpha"))
			mustWrite(t, filepath.Join(src, "box_b", "sk_2"), []byte("bravo"))
			archive, cleanup := archiveLayout(src)
			defer cleanup()

			// Deliberately pick a target with a different basename
			// than the source tree — this is the exact failure the
			// patch fixes.
			target := filepath.Join(t.TempDir(), "differently-named-root")

			cmd := exec.Command("bash", extractor, archive, target)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("extract: %v\n%s", err, out)
			}
			// After extraction, target/box_a/sk_1 and
			// target/box_b/sk_2 must exist with the right bytes.
			for rel, want := range map[string]string{
				"box_a/sk_1": "alpha",
				"box_b/sk_2": "bravo",
			} {
				p := filepath.Join(target, rel)
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("missing %s: %v\ntar output:\n%s", p, err, out)
				}
				if string(b) != want {
					t.Fatalf("%s = %q, want %q", p, string(b), want)
				}
			}
			// Negative: target must NOT have a child directory whose
			// name matches the source basename (the bug the patch
			// fixes). This guards against a future refactor
			// accidentally restoring the old behavior.
			srcBase := filepath.Base(src)
			if _, err := os.Stat(filepath.Join(target, srcBase)); err == nil {
				t.Fatalf("extractor leaked source basename %q into target", srcBase)
			}
		})
	}

	// New content-style layout: tar -C src -czf out.tgz .
	run("content-style", func(root string) (string, func()) {
		tmp := t.TempDir()
		archive := filepath.Join(tmp, "content.tgz")
		cmd := exec.Command("tar", "-C", root, "-czf", archive, ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build content-style archive: %v\n%s", err, out)
		}
		return archive, func() {}
	})

	// Legacy named-top-dir layout: tar -C dirname(src) -czf out.tgz basename(src)
	run("legacy-top-dir", func(root string) (string, func()) {
		tmp := t.TempDir()
		archive := filepath.Join(tmp, "legacy.tgz")
		cmd := exec.Command("tar",
			"-C", filepath.Dir(root), "-czf", archive, filepath.Base(root))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build legacy archive: %v\n%s", err, out)
		}
		return archive, func() {}
	})
}

func mustWrite(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}
