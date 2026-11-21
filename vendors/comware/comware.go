package comware

import (
	"context"
	"strings"

	"github.com/gatework/netops/config"
	"github.com/gatework/netops/device"
	"github.com/gatework/netops/evidence"
	"github.com/gatework/netops/parse"

	"github.com/gatework/baseline"
	"github.com/gatework/baseline/internal/token"
)

// Name is the vendor key of this extractor.
const Name = "comware"

// Extractor decodes Comware configurations. It is stateless and safe for
// concurrent use.
type Extractor struct{}

// New returns a Comware extractor.
func New() *Extractor { return &Extractor{} }

// Vendor returns "comware".
func (*Extractor) Vendor() string { return Name }

// Dialect returns the Comware configuration dialect.
func (*Extractor) Dialect() config.Dialect { return config.Comware() }

// Extract builds the posture of d from doc.
func (*Extractor) Extract(ctx context.Context, d device.Device, doc *config.Document) (baseline.Extraction, error) {
	x := &extraction{
		p:         &baseline.Posture{Device: d, Config: doc, ACLs: map[string]baseline.ACL{}},
		tally:     baseline.NewTally(d.ID, Name, baseline.Facets()...),
		lineClass: map[baseline.LineKind]*parse.Node{},
	}
	x.p.AAA.Default = "system"
	x.p.SNMP.Versions = []string{"v3"}
	x.p.Logging.State = baseline.StateEnabled
	x.p.Time.NTPState = baseline.StateDisabled
	x.p.SNMP.State = baseline.StateDisabled
	for _, s := range []*baseline.Service{&x.p.Services.Telnet, &x.p.Services.SSH, &x.p.Services.SSHv1,
		&x.p.Services.HTTP, &x.p.Services.HTTPS, &x.p.Services.NETCONF} {
		s.State = baseline.StateDisabled
	}
	for i, n := range doc.Root().Children {
		if i%256 == 0 && ctx.Err() != nil {
			return baseline.Extraction{}, ctx.Err()
		}
		x.statement(n)
	}
	x.finish()
	return x.tally.Result(x.p), nil
}

// extraction is the state of one Extract call.
type extraction struct {
	p         *baseline.Posture
	tally     *baseline.Tally
	lineClass map[baseline.LineKind]*parse.Node
	lines     []*parse.Node
}

// statement dispatches one top-level statement or block.
func (x *extraction) statement(n *parse.Node) {
	w := token.Split(n.Text)
	undo := w.At(0) == "undo"
	if undo {
		w = w.From(1)
	}
	switch w.At(0) {
	case "sysname":
		x.p.Hostname = w.At(1)
	case "version":
		x.p.Version = strings.TrimSpace(strings.TrimPrefix(n.Text, "version"))
	case "hwtacacs", "radius":
		x.aaaScheme(n, w)
	case "domain":
		x.domain(n, w, undo)
	case "local-user":
		x.account(n, w)
	case "line", "user-interface":
		x.line(n, w)
	case "ssh", "telnet", "stelnet", "sftp", "scp", "netconf":
		x.service(n, w, undo)
	case "ip":
		if w.At(1) == "http" || w.At(1) == "https" {
			x.service(n, w, undo)
		}
	case "info-center":
		x.logging(n, w, undo)
	case "ntp-service":
		x.ntp(n, w, undo)
	case "clock":
		x.clock(n, w)
	case "snmp-agent":
		x.snmp(n, w, undo)
	case "dot1x", "mac-authentication":
		x.nac(n, w, undo)
	case "interface":
		x.iface(n, w)
	case "acl":
		x.acl(n, w)
	}
}

// finish resolves what depends on the whole configuration: line classes
// and the default domain.
func (x *extraction) finish() {
	for _, n := range x.lines {
		x.p.Lines = append(x.p.Lines, x.decodeLine(n))
	}
	if _, ok := x.p.AAA.Set(x.p.AAA.Default); !ok && x.p.AAA.Default == "system" {
		local := baseline.MethodList{{Kind: baseline.MethodLocal}}
		x.p.AAA.Sets = append(x.p.AAA.Sets, baseline.MethodSet{
			Name: "system", Login: local, Authorization: local, Accounting: local,
		})
	}
	for _, i := range x.p.Interfaces {
		x.p.NAC.AddDomain(i.Domain)
	}
}

// unknown records n as an undecoded statement of facet.
func (x *extraction) unknown(n *parse.Node, facet evidence.Dimension) {
	x.tally.Unrecognized(facet, n.Line.Number, token.Keyword(n, x.p.Config.Dialect()))
}
