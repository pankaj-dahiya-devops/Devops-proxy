package policy

import "testing"

func TestGetThreshold_NilConfig(t *testing.T) {
	got := GetThreshold("EC2_LOW_CPU", "cpu_threshold", 10.0, nil)
	if got != 10.0 {
		t.Errorf("got %.1f; want 10.0 (nil cfg must return default)", got)
	}
}

func TestGetThreshold_RuleNotPresent(t *testing.T) {
	cfg := &PolicyConfig{Rules: map[string]RuleConfig{}}
	got := GetThreshold("EC2_LOW_CPU", "cpu_threshold", 10.0, cfg)
	if got != 10.0 {
		t.Errorf("got %.1f; want 10.0 (rule absent must return default)", got)
	}
}

func TestGetThreshold_ParamNotPresent(t *testing.T) {
	cfg := &PolicyConfig{
		Rules: map[string]RuleConfig{
			"EC2_LOW_CPU": {Params: map[string]float64{}},
		},
	}
	got := GetThreshold("EC2_LOW_CPU", "cpu_threshold", 10.0, cfg)
	if got != 10.0 {
		t.Errorf("got %.1f; want 10.0 (param absent must return default)", got)
	}
}

func TestGetThreshold_NilParamsMap(t *testing.T) {
	cfg := &PolicyConfig{
		Rules: map[string]RuleConfig{
			"EC2_LOW_CPU": {Params: nil},
		},
	}
	got := GetThreshold("EC2_LOW_CPU", "cpu_threshold", 10.0, cfg)
	if got != 10.0 {
		t.Errorf("got %.1f; want 10.0 (nil Params map must return default)", got)
	}
}

func TestGetThreshold_OverrideValue(t *testing.T) {
	cfg := &PolicyConfig{
		Rules: map[string]RuleConfig{
			"EC2_LOW_CPU": {
				Params: map[string]float64{"cpu_threshold": 15.0},
			},
		},
	}
	got := GetThreshold("EC2_LOW_CPU", "cpu_threshold", 10.0, cfg)
	if got != 15.0 {
		t.Errorf("got %.1f; want 15.0 (configured override must be returned)", got)
	}
}

func TestGetThreshold_DifferentRuleIsolated(t *testing.T) {
	// Override for NAT_LOW_TRAFFIC must not affect EC2_LOW_CPU lookup.
	cfg := &PolicyConfig{
		Rules: map[string]RuleConfig{
			"NAT_LOW_TRAFFIC": {
				Params: map[string]float64{"traffic_gb_threshold": 5.0},
			},
		},
	}
	got := GetThreshold("EC2_LOW_CPU", "cpu_threshold", 10.0, cfg)
	if got != 10.0 {
		t.Errorf("got %.1f; want 10.0 (override for different rule must not bleed over)", got)
	}
}
