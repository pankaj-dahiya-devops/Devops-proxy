package policy

// GetThreshold returns the configured float64 parameter value for a rule, or
// defaultValue when no override is present. It is safe to call with cfg == nil.
//
// Lookup order:
//  1. cfg == nil → defaultValue
//  2. cfg.Rules[ruleID] absent → defaultValue
//  3. cfg.Rules[ruleID].Params[key] absent → defaultValue
//  4. Otherwise → configured value
func GetThreshold(ruleID, key string, defaultValue float64, cfg *PolicyConfig) float64 {
	if cfg == nil {
		return defaultValue
	}
	rc, ok := cfg.Rules[ruleID]
	if !ok {
		return defaultValue
	}
	v, ok := rc.Params[key]
	if !ok {
		return defaultValue
	}
	return v
}
