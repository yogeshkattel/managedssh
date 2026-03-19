package rbac

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Role defines the permission level for a profile.
type Role string

const (
	RoleAdmin    Role = "admin"    // Full access: add/edit/delete/connect/export/change-key
	RoleOperator Role = "operator" // Connect + view: can connect, search, view — cannot add/edit/delete/export/change-key
	RoleViewer   Role = "viewer"   // View only: can browse host list but cannot connect or modify
)

var ErrPermissionDenied = errors.New("permission denied")

// Permission represents an action that can be checked.
type Permission string

const (
	PermConnect       Permission = "connect"
	PermAddHost       Permission = "add_host"
	PermEditHost      Permission = "edit_host"
	PermDeleteHost    Permission = "delete_host"
	PermExport        Permission = "export"
	PermImport        Permission = "import"
	PermChangeKey     Permission = "change_key"
	PermViewHosts     Permission = "view_hosts"
	PermLock          Permission = "lock"
	PermHealthCheck   Permission = "health_check"
	PermViewAnalytics Permission = "view_analytics"
	PermManageKeys    Permission = "manage_keys"
	PermViewSessions  Permission = "view_sessions"
	PermManageRoles   Permission = "manage_roles"
)

var rolePermissions = map[Role]map[Permission]bool{
	RoleAdmin: {
		PermConnect:       true,
		PermAddHost:       true,
		PermEditHost:      true,
		PermDeleteHost:    true,
		PermExport:        true,
		PermImport:        true,
		PermChangeKey:     true,
		PermViewHosts:     true,
		PermLock:          true,
		PermHealthCheck:   true,
		PermViewAnalytics: true,
		PermManageKeys:    true,
		PermViewSessions:  true,
		PermManageRoles:   true,
	},
	RoleOperator: {
		PermConnect:       true,
		PermViewHosts:     true,
		PermLock:          true,
		PermHealthCheck:   true,
		PermViewAnalytics: true,
	},
	RoleViewer: {
		PermViewHosts: true,
	},
}

// Config stores the RBAC configuration for a profile.
type Config struct {
	Role Role `json:"role"`
	path string
}

// ValidRoles returns all valid role names.
func ValidRoles() []Role {
	return []Role{RoleAdmin, RoleOperator, RoleViewer}
}

// IsValidRole checks if a role string is valid.
func IsValidRole(r string) bool {
	switch Role(strings.ToLower(r)) {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	}
	return false
}

// Load reads the RBAC config from the given vault directory.
// Returns admin role if no config exists (backward compatible).
func Load(dir string) (*Config, error) {
	p := filepath.Join(dir, "rbac.json")
	c := &Config{Role: RoleAdmin, path: p}

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	c.path = p
	return c, nil
}

// Save persists the RBAC config to disk.
func (c *Config) Save() error {
	dir := filepath.Dir(c.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// SetRole updates the role.
func (c *Config) SetRole(role Role) error {
	if !IsValidRole(string(role)) {
		return fmt.Errorf("invalid role: %s", role)
	}
	c.Role = role
	return c.Save()
}

// Can checks if the current role has a given permission.
func (c *Config) Can(perm Permission) bool {
	perms, ok := rolePermissions[c.Role]
	if !ok {
		return false
	}
	return perms[perm]
}

// Check returns an error if the current role lacks the permission.
func (c *Config) Check(perm Permission) error {
	if !c.Can(perm) {
		return fmt.Errorf("%w: %s role cannot %s", ErrPermissionDenied, c.Role, perm)
	}
	return nil
}

// RoleLabel returns a human-readable label for a role.
func RoleLabel(r Role) string {
	switch r {
	case RoleAdmin:
		return "Admin (full access)"
	case RoleOperator:
		return "Operator (connect + view)"
	case RoleViewer:
		return "Viewer (read-only)"
	default:
		return string(r)
	}
}
