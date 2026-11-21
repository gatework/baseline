package baseline

import (
	"fmt"
	"slices"
	"time"
)

// LineKind is the kind of a login line.
type LineKind string

// Line kinds.
const (
	LineConsole LineKind = "console"
	LineAux     LineKind = "aux"
	LineVTY     LineKind = "vty"
)

// LineAuth is how a line authenticates logins.
type LineAuth int

// Line authentication modes.
const (
	LineAuthUnset    LineAuth = iota
	LineAuthNone              // no authentication
	LineAuthPassword          // a static line password
	LineAuthAAA               // AAA (H3C scheme, Cisco login authentication)
)

var lineAuthNames = [...]string{"", "none", "password", "aaa"}

// String returns the lowercase name.
func (a LineAuth) String() string {
	if a < 0 || int(a) >= len(lineAuthNames) {
		return fmt.Sprintf("LineAuth(%d)", int(a))
	}
	return lineAuthNames[a]
}

// MarshalText encodes the mode by name.
func (a LineAuth) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// Line is one console, aux or VTY line range, with vendor defaults
// already applied by the extractor.
type Line struct {
	Kind  LineKind `json:"kind"`
	Range string   `json:"range"` // "0 4", "0", "" for a single line
	Auth  LineAuth `json:"auth"`
	// PasswordSet reports a line password. A password-mode line without one
	// rejects every login.
	PasswordSet bool `json:"password_set,omitempty"`
	// MethodSet names the AAA method set the line uses; empty is the
	// default.
	MethodSet string `json:"method_set,omitempty"`
	// Protocols lists the inbound protocols allowed, such as "ssh" and
	// "telnet"; nil means not applicable (console).
	Protocols []string `json:"protocols,omitempty"`
	// Idle is the idle timeout; 0 with IdleSet means never.
	Idle    time.Duration `json:"idle,omitempty"`
	IdleSet bool          `json:"idle_set,omitempty"`
	ACL     string        `json:"acl,omitempty"` // inbound access class
	// CommandAuthorization and CommandAccounting are per-line switches
	// (H3C); vendors without them leave both false.
	CommandAuthorization bool `json:"command_authorization,omitempty"`
	CommandAccounting    bool `json:"command_accounting,omitempty"`
	Line                 int  `json:"line,omitempty"`
}

// Usable reports whether the line can accept a login at all: a password
// line without a password, or a VTY that allows no protocol, cannot.
func (l Line) Usable() bool {
	if l.Auth == LineAuthPassword && !l.PasswordSet {
		return false
	}
	return l.Kind != LineVTY || len(l.Protocols) > 0
}

// Allows reports whether the line accepts protocol.
func (l Line) Allows(protocol string) bool { return slices.Contains(l.Protocols, protocol) }

// State is a tri-state switch.
type State int

// States.
const (
	StateUnset State = iota
	StateEnabled
	StateDisabled
)

var stateNames = [...]string{"", "enabled", "disabled"}

// String returns the lowercase name.
func (s State) String() string {
	if s < 0 || int(s) >= len(stateNames) {
		return fmt.Sprintf("State(%d)", int(s))
	}
	return stateNames[s]
}

// MarshalText encodes the state by name.
func (s State) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Enabled reports s == StateEnabled.
func (s State) Enabled() bool { return s == StateEnabled }

// Service is one management service on the device, with vendor defaults
// applied: absent configuration yields the vendor's default state.
type Service struct {
	State State  `json:"state"`
	ACL   string `json:"acl,omitempty"`
	Line  int    `json:"line,omitempty"`
}

// Services are the management-plane listeners.
type Services struct {
	Telnet  Service `json:"telnet"`
	SSH     Service `json:"ssh"`
	SSHv1   Service `json:"sshv1"`
	HTTP    Service `json:"http"`
	HTTPS   Service `json:"https"`
	NETCONF Service `json:"netconf"`
}

// Account is a local user that may log in to the device.
type Account struct {
	Name string `json:"name"`
	// Roles are the user roles or privilege levels, such as
	// "network-admin" or "15".
	Roles []string `json:"roles,omitempty"`
	// Services are the login services allowed, such as "ssh" and
	// "terminal"; nil means any (the vendor has no such restriction) and
	// empty means none: the account cannot log in.
	Services []string `json:"services"`
	// Admin reports the highest privilege (network-admin, level 15,
	// superuser).
	Admin bool `json:"admin,omitempty"`
	// Hashed reports a one-way password hash; false with PasswordSet is a
	// reversible or plain password.
	PasswordSet bool `json:"password_set,omitempty"`
	Hashed      bool `json:"hashed,omitempty"`
	Line        int  `json:"line,omitempty"`
}

// CanLogin reports whether some login service is allowed.
func (a Account) CanLogin() bool { return a.Services == nil || len(a.Services) > 0 }

// ACL is a named or numbered access list, kept so that references from
// lines and services can be resolved.
type ACL struct {
	Name  string `json:"name"`
	Rules int    `json:"rules"`
	Line  int    `json:"line,omitempty"`
}
