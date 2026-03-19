package host

import "testing"

func TestHostNormalizeMigratesLegacyFields(t *testing.T) {
	h := Host{
		Alias:       "prod",
		Hostname:    "prod.example.com",
		User:        "root",
		Users:       []string{"ubuntu", "root"},
		AuthType:    "password",
		EncPassword: []byte("secret"),
	}

	h.Normalize()

	if h.DefaultAuthType != "password" {
		t.Fatalf("expected default auth to migrate, got %q", h.DefaultAuthType)
	}
	if len(h.DefaultEncPassword) == 0 {
		t.Fatal("expected default password to migrate")
	}
	if got, want := h.AccountNames(), []string{"root", "ubuntu"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unexpected migrated accounts: %#v", got)
	}
	for _, account := range h.Accounts {
		if !account.UseDefault {
			t.Fatalf("expected migrated account %q to use default auth", account.Username)
		}
	}
}

func TestResolveAccountPrefersUserOverride(t *testing.T) {
	h := Host{
		DefaultAuthType:    "password",
		DefaultEncPassword: []byte("host-secret"),
		Accounts: []HostUser{
			{Username: "root", UseDefault: true},
			{Username: "deploy", AuthType: "key", KeyPath: "/tmp/deploy-key"},
			{Username: "backup", AuthType: "password", EncPassword: []byte("backup-secret")},
		},
	}

	h.Normalize()

	_, resolved, ok := h.ResolveAccount("root")
	if !ok || resolved.AuthType != "password" || string(resolved.Password) != "host-secret" {
		t.Fatalf("unexpected default account resolution: ok=%v auth=%q password=%q", ok, resolved.AuthType, string(resolved.Password))
	}

	_, resolved, ok = h.ResolveAccount("deploy")
	if !ok || resolved.AuthType != "key" || resolved.KeyPath != "/tmp/deploy-key" || len(resolved.EncKey) != 0 {
		t.Fatalf("unexpected key override resolution: ok=%v auth=%q key_path=%q enc_key=%d", ok, resolved.AuthType, resolved.KeyPath, len(resolved.EncKey))
	}

	_, resolved, ok = h.ResolveAccount("backup")
	if !ok || resolved.AuthType != "password" || string(resolved.Password) != "backup-secret" {
		t.Fatalf("unexpected password override resolution: ok=%v auth=%q password=%q", ok, resolved.AuthType, string(resolved.Password))
	}
}

func TestResolveAccountReturnsDefaultInlineKey(t *testing.T) {
	h := Host{
		DefaultAuthType:   "key",
		DefaultEncKey:     []byte("inline-key"),
		DefaultEncKeyPass: []byte("inline-pass"),
		Accounts: []HostUser{
			{Username: "root", UseDefault: true},
		},
	}

	h.Normalize()

	_, resolved, ok := h.ResolveAccount("root")
	if !ok || resolved.AuthType != "key" || string(resolved.EncKey) != "inline-key" || string(resolved.EncKeyPass) != "inline-pass" {
		t.Fatalf("unexpected default key resolution: ok=%v auth=%q enc_key=%q enc_key_pass=%q", ok, resolved.AuthType, string(resolved.EncKey), string(resolved.EncKeyPass))
	}
}

func TestNormalizeClearsKeyPassphraseForPasswordAuth(t *testing.T) {
	h := Host{
		DefaultAuthType:    "password",
		DefaultEncPassword: []byte("pw"),
		DefaultEncKeyPass:  []byte("should-clear"),
		Accounts: []HostUser{
			{Username: "root", UseDefault: true},
			{Username: "deploy", AuthType: "password", EncPassword: []byte("pw2"), EncKeyPass: []byte("should-clear")},
		},
	}

	h.Normalize()

	if len(h.DefaultEncKeyPass) != 0 {
		t.Fatalf("expected default key passphrase to clear, got %q", string(h.DefaultEncKeyPass))
	}
	if len(h.Accounts[1].EncKeyPass) != 0 {
		t.Fatalf("expected override key passphrase to clear, got %q", string(h.Accounts[1].EncKeyPass))
	}
}
