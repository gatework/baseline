package check

import (
	"slices"
	"strings"
	"time"

	"github.com/gatework/netops/assess"

	"github.com/gatework/baseline"
)

func lineRules() []Rule {
	f := facets(baseline.FacetLine)
	return []Rule{
		assess.Check(meta("line.vty_aaa", titleLineVTYAAA, assess.SeverityHigh, assess.CategorySecurity, f), vtyAAA),
		assess.Check(meta("line.vty_ssh_only", titleLineVTYSSHOnly, assess.SeverityMedium, assess.CategorySecurity, f),
			vtySSHOnly),
		assess.Check(meta("line.idle_timeout", titleLineIdle, assess.SeverityLow, assess.CategorySecurity, f,
			assess.Integer("max_minutes", 15)), idleTimeout),
		assess.Check(meta("line.console_auth", titleLineConsoleAuth, assess.SeverityMedium, assess.CategorySecurity,
			facets(baseline.FacetLine, baseline.FacetAAA)), consoleAuth),
	}
}

func serviceRules() []Rule {
	f := facets(baseline.FacetService)
	off := func(id assess.RuleID, title string, sev assess.Severity, name string, svc func(baseline.Services) baseline.Service) Rule {
		return assess.Check(meta(id, title, sev, assess.CategorySecurity, f), func(in Input) []assess.Finding {
			p := in.Model
			s := svc(p.Services)
			if !s.State.Enabled() {
				return nil
			}
			return []assess.Finding{found(p, device(p).Child("service", name), s.Line, fixService, detailServiceEnabled, name)}
		})
	}
	return []Rule{
		off("service.telnet", titleServiceTelnet, assess.SeverityHigh, "telnet", func(s baseline.Services) baseline.Service { return s.Telnet }),
		off("service.http", titleServiceHTTP, assess.SeverityMedium, "http", func(s baseline.Services) baseline.Service { return s.HTTP }),
		off("service.sshv1", titleServiceSSHv1, assess.SeverityHigh, "sshv1", func(s baseline.Services) baseline.Service { return s.SSHv1 }),
		assess.Check(meta("service.ssh", titleServiceSSH, assess.SeverityMedium, assess.CategoryConfiguration, f),
			func(in Input) []assess.Finding {
				return enabled(in.Model, in.Model.Services.SSH.State, "SSH", fixService)
			}),
		assess.Check(meta("service.ssh_acl", titleServiceSSHACL, assess.SeverityHigh, assess.CategorySecurity,
			facets(baseline.FacetService, baseline.FacetACL)), sshACL),
	}
}

func accountRules() []Rule {
	f := facets(baseline.FacetAccount)
	return []Rule{
		assess.Check(meta("account.forbidden", titleAccountForbidden, assess.SeverityHigh, assess.CategorySecurity, f,
			assess.List("names", "h3c", "cisco", "test", "test123", "guest", "user", "huawei")), accountForbidden),
		assess.Check(meta("account.allowed", titleAccountAllowed, assess.SeverityMedium, assess.CategoryCompliance, f,
			assess.List("names")), accountAllowed),
		assess.Check(meta("account.password_hash", titleAccountHash, assess.SeverityMedium, assess.CategorySecurity, f),
			passwordHash),
		assess.Check(meta("account.password_set", titleAccountPassword, assess.SeverityHigh, assess.CategorySecurity, f),
			passwordSet),
		assess.Check(meta("account.services", titleAccountServices, assess.SeverityMedium, assess.CategorySecurity, f,
			assess.List("forbidden", "telnet", "http", "ftp")), accountServices),
	}
}

func lineSubject(p *baseline.Posture, l baseline.Line) assess.Subject {
	return device(p).Child("line", lineName(l))
}

// lineName is "vty 0 4", or the kind alone for a single line.
func lineName(l baseline.Line) string { return strings.TrimSpace(string(l.Kind) + " " + l.Range) }

func vtyAAA(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, l := range p.LinesOf(baseline.LineVTY) {
		if l.Usable() && l.Auth != baseline.LineAuthAAA {
			out = append(out, found(p, lineSubject(p, l), l.Line, fixLine, detailVTYAuth, lineName(l), l.Auth))
		}
	}
	return out
}

func vtySSHOnly(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, l := range p.LinesOf(baseline.LineVTY) {
		if l.Usable() && l.Allows("telnet") {
			out = append(out, found(p, lineSubject(p, l), l.Line, fixLine, detailVTYTelnet, lineName(l)))
		}
	}
	return out
}

func idleTimeout(in Input) []assess.Finding {
	p := in.Model
	limit := time.Duration(in.Params.Integer("max_minutes")) * time.Minute
	var out []assess.Finding
	for _, l := range p.Lines {
		if !l.Usable() {
			continue
		}
		sub := lineSubject(p, l)
		switch {
		case !l.IdleSet:
			out = append(out, found(p, sub, l.Line, fixLine, detailIdleUnset, lineName(l)))
		case l.Idle == 0:
			out = append(out, found(p, sub, l.Line, fixLine, detailIdleNever, lineName(l)))
		case l.Idle > limit:
			out = append(out, found(p, sub, l.Line, fixLine, detailIdleLong, lineName(l), l.Idle, in.Params.Integer("max_minutes")))
		}
	}
	return out
}

func consoleAuth(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, l := range p.Lines {
		if l.Kind == baseline.LineVTY {
			continue
		}
		none := l.Auth == baseline.LineAuthNone
		if l.Auth == baseline.LineAuthAAA {
			set, ok := p.AAA.Management(l.MethodSet)
			none = ok && len(set.Login) > 0 && set.Login[0].Kind == baseline.MethodNone
		}
		if none {
			out = append(out, found(p, lineSubject(p, l), l.Line, fixLine, detailConsoleNone, lineName(l)))
		}
	}
	return out
}

// sshACL passes when the SSH service has an ACL, or every usable VTY line
// that accepts SSH has one; every referenced ACL must be defined.
func sshACL(in Input) []assess.Finding {
	p := in.Model
	if !p.Services.SSH.State.Enabled() {
		return nil
	}
	sub := device(p).Child("service", "ssh")
	var out []assess.Finding
	var bare []string
	for _, l := range p.LinesOf(baseline.LineVTY) {
		if !l.Usable() || !l.Allows("ssh") {
			continue
		}
		switch {
		case l.ACL == "":
			bare = append(bare, lineName(l))
		case !p.HasACL(l.ACL):
			out = append(out, found(p, lineSubject(p, l), l.Line, fixService, detailACLUndefined, l.ACL))
		}
	}
	switch acl := p.Services.SSH.ACL; {
	case acl != "" && !p.HasACL(acl):
		out = append(out, found(p, sub, p.Services.SSH.Line, fixService, detailACLUndefined, acl))
	case acl == "" && len(bare) > 0:
		out = append(out, found(p, sub, p.Services.SSH.Line, fixService, detailSSHNoACL, strings.Join(bare, ", ")))
	}
	return out
}

func accountForbidden(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, a := range p.Accounts {
		if anyGlob(in.Params.List("names"), a.Name) {
			out = append(out, found(p, device(p).Child("account", a.Name), a.Line, fixAccount, detailAccount, a.Name))
		}
	}
	return out
}

func accountAllowed(in Input) []assess.Finding {
	p := in.Model
	allowed := in.Params.List("names")
	if len(allowed) == 0 {
		return nil
	}
	var out []assess.Finding
	for _, a := range p.Accounts {
		if !anyGlob(allowed, a.Name) {
			out = append(out, found(p, device(p).Child("account", a.Name), a.Line, fixAccount, detailAccount, a.Name))
		}
	}
	return out
}

func passwordHash(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, a := range p.Accounts {
		if a.PasswordSet && !a.Hashed {
			out = append(out, found(p, device(p).Child("account", a.Name), a.Line, fixAccount, detailAccountPlain, a.Name))
		}
	}
	return out
}

func passwordSet(in Input) []assess.Finding {
	p := in.Model
	var out []assess.Finding
	for _, a := range p.Accounts {
		if !a.PasswordSet && a.CanLogin() {
			out = append(out, found(p, device(p).Child("account", a.Name), a.Line, fixAccount, detailAccountNoPass, a.Name))
		}
	}
	return out
}

func accountServices(in Input) []assess.Finding {
	p := in.Model
	forbidden := in.Params.List("forbidden")
	var out []assess.Finding
	for _, a := range p.Accounts {
		var bad []string
		for _, s := range a.Services {
			if slices.Contains(forbidden, s) && !slices.Contains(bad, s) {
				bad = append(bad, s)
			}
		}
		if len(bad) > 0 {
			out = append(out, found(p, device(p).Child("account", a.Name), a.Line, fixAccount, detailAccountServices, a.Name,
				strings.Join(bad, ", ")))
		}
	}
	return out
}
