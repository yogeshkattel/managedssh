package keymgr

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListKeysEmpty(t *testing.T) {
	// Create a temp dir to act as ~/.ssh/ — we can't fully test this without mocking UserHomeDir
	// but we can verify the function doesn't crash.
	keys, err := ListKeys()
	if err != nil {
		t.Fatal(err)
	}
	// Can't assert exact count since it depends on the system, just verify no error.
	_ = keys
}

func TestGenerateAndDeleteEd25519(t *testing.T) {
	// Create a temp dir and override HOME for the test.
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	sshDir := filepath.Join(tmpHome, ".ssh")

	kp, err := GenerateEd25519("test_key", "test@managedssh")
	if err != nil {
		t.Fatal(err)
	}

	if kp.Name != "test_key" {
		t.Fatalf("expected name test_key, got %s", kp.Name)
	}
	if len(kp.PrivateKey) == 0 {
		t.Fatal("private key should not be empty")
	}
	if len(kp.PublicKey) == 0 {
		t.Fatal("public key should not be empty")
	}

	// Verify files exist.
	privPath := filepath.Join(sshDir, "test_key")
	pubPath := filepath.Join(sshDir, "test_key.pub")

	if _, err := os.Stat(privPath); err != nil {
		t.Fatal("private key file should exist")
	}
	if _, err := os.Stat(pubPath); err != nil {
		t.Fatal("public key file should exist")
	}

	// Check private key permissions.
	info, _ := os.Stat(privPath)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions on private key, got %04o", info.Mode().Perm())
	}

	// Read public key.
	pub, err := ReadPublicKey("test_key")
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) == 0 {
		t.Fatal("ReadPublicKey should return data")
	}

	// List keys.
	keys, err := ListKeys()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range keys {
		if k == "test_key" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("test_key should appear in ListKeys")
	}

	// Delete.
	err = DeleteKey("test_key")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(privPath); !os.IsNotExist(err) {
		t.Fatal("private key should be deleted")
	}
	if _, err := os.Stat(pubPath); !os.IsNotExist(err) {
		t.Fatal("public key should be deleted")
	}
}

func TestGenerateDuplicate(t *testing.T) {
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	_, err := GenerateEd25519("dup_test", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = GenerateEd25519("dup_test", "")
	if err == nil {
		t.Fatal("expected error on duplicate key name")
	}
}

func TestGenerateEmptyName(t *testing.T) {
	_, err := GenerateEd25519("", "")
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestValidateKeyNameRejectsPaths(t *testing.T) {
	invalid := []string{"../escape", "nested/key", `nested\key`, ".", "..", "bad key"}
	for _, name := range invalid {
		if err := ValidateKeyName(name); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
}

func TestDeleteNonexistent(t *testing.T) {
	tmpHome := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	err := DeleteKey("nonexistent_key")
	if err != nil {
		t.Fatal("deleting nonexistent key should not error")
	}
}
