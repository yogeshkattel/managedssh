package rbac

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRoleIsAdmin(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Role != RoleAdmin {
		t.Fatalf("expected default role admin, got %s", cfg.Role)
	}
}

func TestAdminHasAllPermissions(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := Load(dir)

	perms := []Permission{
		PermConnect, PermAddHost, PermEditHost, PermDeleteHost,
		PermExport, PermImport, PermChangeKey, PermViewHosts, PermLock,
		PermHealthCheck, PermViewAnalytics, PermManageKeys, PermViewSessions, PermManageRoles,
	}
	for _, p := range perms {
		if !cfg.Can(p) {
			t.Fatalf("admin should have permission %s", p)
		}
	}
}

func TestOperatorPermissions(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := Load(dir)
	cfg.SetRole(RoleOperator)

	if !cfg.Can(PermConnect) {
		t.Fatal("operator should be able to connect")
	}
	if !cfg.Can(PermViewHosts) {
		t.Fatal("operator should be able to view hosts")
	}
	if cfg.Can(PermAddHost) {
		t.Fatal("operator should not be able to add hosts")
	}
	if !cfg.Can(PermHealthCheck) {
		t.Fatal("operator should be able to run health checks")
	}
	if !cfg.Can(PermViewAnalytics) {
		t.Fatal("operator should be able to view analytics")
	}
	if cfg.Can(PermDeleteHost) {
		t.Fatal("operator should not be able to delete hosts")
	}
	if cfg.Can(PermChangeKey) {
		t.Fatal("operator should not be able to change key")
	}
	if cfg.Can(PermManageKeys) {
		t.Fatal("operator should not be able to manage keys")
	}
}

func TestViewerPermissions(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := Load(dir)
	cfg.SetRole(RoleViewer)

	if !cfg.Can(PermViewHosts) {
		t.Fatal("viewer should be able to view hosts")
	}
	if cfg.Can(PermConnect) {
		t.Fatal("viewer should not be able to connect")
	}
	if cfg.Can(PermAddHost) {
		t.Fatal("viewer should not be able to add hosts")
	}
	if cfg.Can(PermEditHost) {
		t.Fatal("viewer should not be able to edit hosts")
	}
	if cfg.Can(PermDeleteHost) {
		t.Fatal("viewer should not be able to delete hosts")
	}
}

func TestCheckReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := Load(dir)
	cfg.SetRole(RoleViewer)

	err := cfg.Check(PermConnect)
	if err == nil {
		t.Fatal("expected permission denied error")
	}
	if !Contains(err.Error(), "permission denied") {
		t.Fatalf("expected 'permission denied', got %q", err.Error())
	}
}

func TestSetInvalidRole(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := Load(dir)
	err := cfg.SetRole("superadmin")
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	cfg1, _ := Load(dir)
	cfg1.SetRole(RoleOperator)

	cfg2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Role != RoleOperator {
		t.Fatalf("expected persisted role operator, got %s", cfg2.Role)
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := Load(dir)
	cfg.SetRole(RoleAdmin)

	info, err := os.Stat(filepath.Join(dir, "rbac.json"))
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("expected 0600 permissions, got %04o", perm)
	}
}

func TestIsValidRole(t *testing.T) {
	if !IsValidRole("admin") {
		t.Fatal("admin should be valid")
	}
	if !IsValidRole("OPERATOR") {
		t.Fatal("OPERATOR should be valid (case insensitive)")
	}
	if !IsValidRole("viewer") {
		t.Fatal("viewer should be valid")
	}
	if IsValidRole("root") {
		t.Fatal("root should be invalid")
	}
	if IsValidRole("") {
		t.Fatal("empty should be invalid")
	}
}

func TestValidRoles(t *testing.T) {
	roles := ValidRoles()
	if len(roles) != 3 {
		t.Fatalf("expected 3 valid roles, got %d", len(roles))
	}
}

func TestRoleLabel(t *testing.T) {
	if RoleLabel(RoleAdmin) == "" {
		t.Fatal("admin label should not be empty")
	}
	if RoleLabel(RoleOperator) == "" {
		t.Fatal("operator label should not be empty")
	}
	if RoleLabel(RoleViewer) == "" {
		t.Fatal("viewer label should not be empty")
	}
}

// Contains is a helper since strings.Contains is not in testing by default.
func Contains(s, substr string) bool {
	return len(s) >= len(substr) && containsImpl(s, substr)
}

func containsImpl(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
