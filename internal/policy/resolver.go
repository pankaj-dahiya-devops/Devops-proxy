package policy

import (
	"strings"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

func ApplyPolicy(findings []models.Finding, domain string, cfg *PolicyConfig) []models.Finding {
	if cfg == nil {
		return findings
	}

	// Domain-level disable
	if d, ok := cfg.Domains[domain]; ok {
		if !d.Enabled {
			return []models.Finding{}
		}
	}

	var result []models.Finding

	for _, f := range findings {
		ruleCfg, hasRule := cfg.Rules[f.RuleID]

		// Rule-level disable
		if hasRule && ruleCfg.Enabled != nil && !*ruleCfg.Enabled {
			continue
		}

		// Severity override
		if hasRule && ruleCfg.Severity != "" {
			f.Severity = models.Severity(strings.ToUpper(ruleCfg.Severity))
		}

		result = append(result, f)
	}

	return result
}