package policy

import (
	"fmt"
	"strings"
)

// validDomains is the set of recognised audit domain names.
var validDomains = map[string]struct{}{
	"cost":           {},
	"security":       {},
	"dataprotection": {},
}

// validSeverities is the set of allowed severity strings (upper-case canonical form).
var validSeverities = map[string]struct{}{
	"CRITICAL": {},
	"HIGH":     {},
	"MEDIUM":   {},
	"LOW":      {},
	"INFO":     {},
}

// Validate checks cfg for semantic correctness and returns all validation errors
// found. An empty slice means the config is valid.
//
// Checks performed:
//   - version must be 1
//   - domain names must be one of: cost, security, dataprotection
//   - domain min_severity must be a valid severity value if set
//   - rule IDs must appear in availableRuleIDs
//   - rule severity overrides must be valid severity values if set
//   - enforcement domain names must be one of: cost, security, dataprotection
//   - enforcement fail_on_severity must be a valid severity value if set
//
// All errors are collected before returning; Validate never stops at the first error.
func Validate(cfg *PolicyConfig, availableRuleIDs []string) []error {
	if cfg == nil {
		return []error{fmt.Errorf("policy config is nil")}
	}

	// Build a lookup set for fast rule ID membership tests.
	knownIDs := make(map[string]struct{}, len(availableRuleIDs))
	for _, id := range availableRuleIDs {
		knownIDs[id] = struct{}{}
	}

	var errs []error

	// Version check.
	if cfg.Version != 1 {
		errs = append(errs, fmt.Errorf("version: unsupported value %d; must be 1", cfg.Version))
	}

	// Domain checks.
	for name, dcfg := range cfg.Domains {
		if _, ok := validDomains[name]; !ok {
			errs = append(errs, fmt.Errorf("domains.%s: unknown domain; valid values: cost, security, dataprotection", name))
		}
		if dcfg.MinSeverity != "" {
			upper := strings.ToUpper(dcfg.MinSeverity)
			if _, ok := validSeverities[upper]; !ok {
				errs = append(errs, fmt.Errorf("domains.%s.min_severity: invalid value %q; valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO", name, dcfg.MinSeverity))
			}
		}
	}

	// Rule checks.
	for ruleID, rcfg := range cfg.Rules {
		if _, ok := knownIDs[ruleID]; !ok {
			errs = append(errs, fmt.Errorf("rules.%s: unknown rule ID", ruleID))
		}
		if rcfg.Severity != "" {
			upper := strings.ToUpper(rcfg.Severity)
			if _, ok := validSeverities[upper]; !ok {
				errs = append(errs, fmt.Errorf("rules.%s.severity: invalid value %q; valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO", ruleID, rcfg.Severity))
			}
		}
	}

	// Enforcement checks.
	for domain, enfCfg := range cfg.Enforcement {
		if _, ok := validDomains[domain]; !ok {
			errs = append(errs, fmt.Errorf("enforcement.%s: unknown domain; valid values: cost, security, dataprotection", domain))
		}
		if enfCfg.FailOnSeverity != "" {
			upper := strings.ToUpper(enfCfg.FailOnSeverity)
			if _, ok := validSeverities[upper]; !ok {
				errs = append(errs, fmt.Errorf("enforcement.%s.fail_on_severity: invalid value %q; valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO", domain, enfCfg.FailOnSeverity))
			}
		}
	}

	return errs
}
