package baseline

import (
	"fmt"
	"slices"
	"strings"
)

// MethodKind is the kind of one AAA method.
type MethodKind int

// Method kinds.
const (
	MethodUnset MethodKind = iota
	MethodGroup            // a remote server group
	MethodLocal            // the local user database
	MethodNone             // no AAA: always succeeds
)

var methodNames = [...]string{"", "group", "local", "none"}

// String returns the lowercase name.
func (k MethodKind) String() string {
	if k < 0 || int(k) >= len(methodNames) {
		return fmt.Sprintf("MethodKind(%d)", int(k))
	}
	return methodNames[k]
}

// MarshalText encodes the kind by name.
func (k MethodKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// Method is one step of a method list.
type Method struct {
	Kind     MethodKind `json:"kind"`
	Protocol string     `json:"protocol,omitempty"` // "tacacs" or "radius" for MethodGroup
	Group    string     `json:"group,omitempty"`    // server group name for MethodGroup
}

// String returns "tacacs:3A", "local" or "none".
func (m Method) String() string {
	if m.Kind == MethodGroup {
		return m.Protocol + ":" + m.Group
	}
	return m.Kind.String()
}

// MethodList is an ordered fallback chain of methods; empty means not
// configured.
type MethodList []Method

// Remote reports whether the first method is a server group.
func (l MethodList) Remote() bool { return len(l) > 0 && l[0].Kind == MethodGroup }

// Has reports whether any method is of kind k.
func (l MethodList) Has(k MethodKind) bool {
	return slices.ContainsFunc(l, func(m Method) bool { return m.Kind == k })
}

// String joins the methods with " > ".
func (l MethodList) String() string {
	parts := make([]string, len(l))
	for i, m := range l {
		parts[i] = m.String()
	}
	return strings.Join(parts, " > ")
}

// MethodSet is the AAA configuration applied to one set of logins: an H3C
// ISP domain, or a Cisco method list name ("default" or a named list).
type MethodSet struct {
	Name string `json:"name"`
	// Login authenticates management logins.
	Login MethodList `json:"login,omitempty"`
	// Authorization authorizes the login session (exec, user role).
	Authorization MethodList `json:"authorization,omitempty"`
	// Commands authorizes each command.
	Commands MethodList `json:"commands,omitempty"`
	// Accounting accounts the login session.
	Accounting MethodList `json:"accounting,omitempty"`
	// CommandAccounting accounts each command.
	CommandAccounting MethodList `json:"command_accounting,omitempty"`
	Line              int        `json:"line,omitempty"`
}

// AAA is the authentication, authorization and accounting configuration.
type AAA struct {
	Groups []ServerGroup `json:"groups,omitempty"`
	Sets   []MethodSet   `json:"sets,omitempty"`
	// Default names the method set that management logins use when a line
	// names none: the H3C default domain, the Cisco "default" list.
	Default string `json:"default,omitempty"`
}

// Group returns the server group named name.
func (a AAA) Group(name string) (ServerGroup, bool) {
	i := slices.IndexFunc(a.Groups, func(g ServerGroup) bool { return g.Name == name })
	if i < 0 {
		return ServerGroup{}, false
	}
	return a.Groups[i], true
}

// Set returns the method set named name.
func (a AAA) Set(name string) (MethodSet, bool) {
	i := slices.IndexFunc(a.Sets, func(s MethodSet) bool { return s.Name == name })
	if i < 0 {
		return MethodSet{}, false
	}
	return a.Sets[i], true
}

// Management returns the method set that management logins use: the set
// named by the line when given, else the default.
func (a AAA) Management(line string) (MethodSet, bool) {
	if line != "" {
		return a.Set(line)
	}
	return a.Set(a.Default)
}

// Servers returns the servers of the groups that list references, in
// method order and then server order, for one function.
func (a AAA) Servers(list MethodList, function string) []Server {
	var out []Server
	for _, m := range list {
		if m.Kind != MethodGroup {
			continue
		}
		if g, ok := a.Group(m.Group); ok {
			out = append(out, g.For(function)...)
		}
	}
	return out
}
