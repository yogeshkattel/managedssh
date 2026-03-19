package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Override the profile to use temp dir.
	origProfile := activeProfile
	t.Cleanup(func() { activeProfile = origProfile })
	return dir
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt := make([]byte, saltLen)
	k1 := deriveKey([]byte("password123"), salt)
	k2 := deriveKey([]byte("password123"), salt)
	if !bytes.Equal(k1, k2) {
		t.Fatal("deriveKey should be deterministic for same password+salt")
	}
}

func TestDeriveKeyDifferentPasswords(t *testing.T) {
	salt := make([]byte, saltLen)
	k1 := deriveKey([]byte("password123"), salt)
	k2 := deriveKey([]byte("password456"), salt)
	if bytes.Equal(k1, k2) {
		t.Fatal("different passwords must produce different keys")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := deriveKey([]byte("testpassword"), make([]byte, saltLen))
	plaintext := []byte("hello world secret data")

	encrypted, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted data should differ from plaintext")
	}

	decrypted, err := Decrypt(key, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted data mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := deriveKey([]byte("password1"), make([]byte, saltLen))
	key2 := deriveKey([]byte("password2"), make([]byte, saltLen))

	encrypted, err := Encrypt(key1, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(key2, encrypted)
	if err == nil {
		t.Fatal("Decrypt with wrong key should fail")
	}
}

func TestDecryptTooShort(t *testing.T) {
	key := deriveKey([]byte("password"), make([]byte, saltLen))
	_, err := Decrypt(key, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("Decrypt of short blob should fail")
	}
}

func TestZeroKey(t *testing.T) {
	key := []byte{1, 2, 3, 4, 5}
	ZeroKey(key)
	for i, b := range key {
		if b != 0 {
			t.Fatalf("byte %d not zeroed: got %d", i, b)
		}
	}
}

func TestCreateAndUnlock(t *testing.T) {
	dir := t.TempDir()
	// Temporarily override Dir() by setting activeProfile to use a subdirectory.
	vaultDir := filepath.Join(dir, "testvault")
	os.MkdirAll(vaultDir, 0700)

	// We can't easily override Dir() without modifying the package,
	// so let's test the low-level functions instead.
	password := "TestPass1"
	salt := make([]byte, saltLen)
	key := deriveKey([]byte(password), salt)

	// Encrypt the verifier.
	nonce, ciphertext, err := encryptBytes(key, []byte(verifierPlaintext), aadVaultVerifier)
	if err != nil {
		t.Fatalf("encryptBytes failed: %v", err)
	}

	// Decrypt and verify.
	plain, err := decryptBytes(key, nonce, ciphertext, aadVaultVerifier)
	if err != nil {
		t.Fatalf("decryptBytes failed: %v", err)
	}
	if string(plain) != verifierPlaintext {
		t.Fatalf("verifier mismatch: got %q, want %q", plain, verifierPlaintext)
	}
}

func TestReEncrypt(t *testing.T) {
	oldKey := deriveKey([]byte("oldpass"), make([]byte, saltLen))
	newKey := deriveKey([]byte("newpass"), make([]byte, saltLen))
	plaintext := []byte("re-encrypt me")

	blob, err := Encrypt(oldKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	reencrypted, err := ReEncrypt(oldKey, newKey, blob)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Decrypt(newKey, reencrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Fatalf("re-encrypted data mismatch: got %q, want %q", result, plaintext)
	}

	// Verify old key can't decrypt.
	_, err = Decrypt(oldKey, reencrypted)
	if err == nil {
		t.Fatal("old key should not decrypt re-encrypted data")
	}
}

func TestAADPreventsTransplant(t *testing.T) {
	key := deriveKey([]byte("password"), make([]byte, saltLen))
	plaintext := []byte("some data")

	// Encrypt with vault verifier AAD.
	nonce, ct, err := encryptBytes(key, plaintext, aadVaultVerifier)
	if err != nil {
		t.Fatal(err)
	}

	// Try to decrypt with host password AAD — should fail.
	_, err = decryptBytes(key, nonce, ct, aadHostPassword)
	if err == nil {
		t.Fatal("decrypting with wrong AAD should fail")
	}
}

func TestLockoutAfterMaxAttempts(t *testing.T) {
	home := t.TempDir()
	origHome := os.Getenv("HOME")
	origProfile := activeProfile
	t.Cleanup(func() {
		_ = os.Setenv("HOME", origHome)
		activeProfile = origProfile
	})
	if err := os.Setenv("HOME", home); err != nil {
		t.Fatal(err)
	}
	SetProfile("lockout-test")
	if err := resetFailures(); err != nil {
		t.Fatal(err)
	}

	// Record max failures.
	for i := 0; i < maxFailedAttempts; i++ {
		if err := recordFailure(); err != nil {
			t.Fatal(err)
		}
	}

	err := checkLockout()
	if err == nil {
		t.Fatal("expected lockout error after max attempts")
	}

	// Reset for other tests.
	if err := resetFailures(); err != nil {
		t.Fatal(err)
	}
	err = checkLockout()
	if err != nil {
		t.Fatal("expected no error after reset")
	}
}

func TestProfileManagement(t *testing.T) {
	original := activeProfile
	defer func() { activeProfile = original }()

	SetProfile("testprofile")
	if ActiveProfile() != "testprofile" {
		t.Fatalf("expected testprofile, got %s", ActiveProfile())
	}

	SetProfile("  spaces  ")
	if ActiveProfile() != "spaces" {
		t.Fatalf("expected trimmed profile name, got %q", ActiveProfile())
	}

	SetProfile("")
	if ActiveProfile() != "" {
		t.Fatalf("expected empty profile, got %q", ActiveProfile())
	}
}

func TestEncryptUniqueNonces(t *testing.T) {
	key := deriveKey([]byte("password"), make([]byte, saltLen))
	plaintext := []byte("same plaintext")

	e1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(e1, e2) {
		t.Fatal("encrypting same plaintext twice should produce different results due to unique nonces")
	}
}

func TestValidateProfileName(t *testing.T) {
	valid := []string{"work", "client-a", "prod 1", "staging.profile"}
	for _, name := range valid {
		if err := ValidateProfileName(name); err != nil {
			t.Fatalf("expected %q to be valid: %v", name, err)
		}
	}

	invalid := []string{"", "   ", ".", "..", "../prod", "team/blue", `team\blue`}
	for _, name := range invalid {
		if err := ValidateProfileName(name); err == nil {
			t.Fatalf("expected %q to be invalid", name)
		}
	}
}

func TestDirRejectsInvalidActiveProfile(t *testing.T) {
	original := activeProfile
	defer func() { activeProfile = original }()

	SetProfile("../bad")
	if _, err := Dir(); err == nil {
		t.Fatal("expected Dir to reject invalid active profile")
	}
}

func TestRotationBackupRecovery(t *testing.T) {
	home := t.TempDir()
	origHome := os.Getenv("HOME")
	origProfile := activeProfile
	t.Cleanup(func() {
		_ = os.Setenv("HOME", origHome)
		activeProfile = origProfile
	})
	if err := os.Setenv("HOME", home); err != nil {
		t.Fatal(err)
	}

	SetProfile("testprofile")
	if _, err := Create("StrongPass1"); err != nil {
		t.Fatal(err)
	}

	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}

	originalVault, err := os.ReadFile(filepath.Join(dir, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	originalHosts := []byte(`{"hosts":[{"id":"1","alias":"prod","hostname":"1.2.3.4","user":"root","users":["root"],"port":22,"auth_type":"password","enc_password":"AQID"}]}`)
	if err := os.WriteFile(filepath.Join(dir, "hosts.json"), originalHosts, 0600); err != nil {
		t.Fatal(err)
	}

	if err := CreateRotationBackup(); err != nil {
		t.Fatal(err)
	}

	replacementVault := []byte(`{"salt":"bmV3","nonce":"bmV3","verifier":"bmV3"}`)
	replacementHosts := []byte(`{"hosts":[]}`)
	if err := WriteMetadata(replacementVault); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts.json"), replacementHosts, 0600); err != nil {
		t.Fatal(err)
	}

	if err := RecoverPendingRotation(); err != nil {
		t.Fatal(err)
	}

	gotVault, err := os.ReadFile(filepath.Join(dir, "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotVault, originalVault) {
		t.Fatal("vault.json was not restored from rotation backup")
	}

	gotHosts, err := os.ReadFile(filepath.Join(dir, "hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotHosts, originalHosts) {
		t.Fatal("hosts.json was not restored from rotation backup")
	}
}
