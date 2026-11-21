package comware

import (
	_ "embed"

	textrule "github.com/gatework/netops/baseline"
)

//go:embed rules.yml
var rulesYAML []byte

// Rules returns the comware best-practice text rules, compiled.
func Rules() ([]textrule.Rule, error) {
	p, err := textrule.Decode(rulesYAML)
	if err != nil {
		return nil, err
	}
	return p.Default.Rules, nil
}
