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
			{Username: "deploy", AuthType: "key"},
			{Username: "backup", AuthType: "password", EncPassword: []byte("backup-secret")},
		},
	}

	h.Normalize()

	_, authType, password, ok := h.ResolveAccount("root")
	if !ok || authType != "password" || string(password) != "host-secret" {
		t.Fatalf("unexpected default account resolution: ok=%v auth=%q password=%q", ok, authType, string(password))
	}

	_, authType, password, ok = h.ResolveAccount("deploy")
	if !ok || authType != "key" || len(password) != 0 {
		t.Fatalf("unexpected key override resolution: ok=%v auth=%q password=%q", ok, authType, string(password))
	}

	_, authType, password, ok = h.ResolveAccount("backup")
	if !ok || authType != "password" || string(password) != "backup-secret" {
		t.Fatalf("unexpected password override resolution: ok=%v auth=%q password=%q", ok, authType, string(password))
	}
}
