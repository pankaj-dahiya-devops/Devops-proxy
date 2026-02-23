package engine

import (
	"context"
	"testing"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/policy"
)

// ── test double ───────────────────────────────────────────────────────────────

// stubAWSEngine returns a fixed report (or error) from RunAudit.
// It satisfies awsDomainEngine.
type stubAWSEngine struct {
	report *models.AuditReport
	err    error
}

func (s *stubAWSEngine) RunAudit(_ context.Context, _ AuditOptions) (*models.AuditReport, error) {
	return s.report, s.err
}

// ── helpers ───────────────────────────────────────────────────────────────────

// newAllAWSEngine builds an AllAWSDomainsEngine wired to three AWS domain stubs.
// There is intentionally no kube parameter: AllAWSDomainsEngine is AWS-only.
func newAllAWSEngine(
	costReport, secReport, dpReport *models.AuditReport,
	policyCfg *policy.PolicyConfig,
) *AllAWSDomainsEngine {
	return &AllAWSDomainsEngine{
		cost:   &stubAWSEngine{report: costReport},
		sec:    &stubAWSEngine{report: secReport},
		dp:     &stubAWSEngine{report: dpReport},
		policy: policyCfg,
	}
}

// emptyDomainReport returns a minimal report with no findings.
func emptyDomainReport(auditType, profile, accountID string, regions []string) *models.AuditReport {
	return &models.AuditReport{
		ReportID:    "test-" + auditType,
		GeneratedAt: time.Now().UTC(),
		AuditType:   auditType,
		Profile:     profile,
		AccountID:   accountID,
		Regions:     regions,
	}
}

// domainReportWith returns a report containing the supplied findings.
func domainReportWith(auditType string, findings []models.Finding) *models.AuditReport {
	return &models.AuditReport{
		ReportID:    "test-" + auditType,
		GeneratedAt: time.Now().UTC(),
		AuditType:   auditType,
		Profile:     "test",
		AccountID:   "111122223333",
		Regions:     []string{"us-east-1"},
		Findings:    findings,
		Summary:     computeSummary(findings),
	}
}

// ── TestAuditAll_MergeBehavior ────────────────────────────────────────────────

// TestAuditAll_MergeBehavior verifies that findings for the same resource from
// two different AWS domains (cost and dataprotection) are merged into a single
// cross-domain finding that carries the highest severity and the sum of savings.
func TestAuditAll_MergeBehavior(t *testing.T) {
	// vol-1 appears in cost (LOW, $5) and dataprotection (HIGH, $0).
	// Cross-domain merge must yield one finding: severity=HIGH, savings=$5.
	costFindings := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNATTACHED", models.SeverityLow, 5.0),
	}
	dpFindings := []models.Finding{
		newFinding("vol-1", "us-east-1", "EBS_UNENCRYPTED", models.SeverityHigh, 0.0),
	}

	eng := newAllAWSEngine(
		domainReportWith("cost", costFindings),
		emptyDomainReport("security", "test", "111122223333", []string{"us-east-1"}),
		domainReportWith("dataprotection", dpFindings),
		nil,
	)

	report, enforced, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(enforced) != 0 {
		t.Errorf("expected no enforced domains; got %v", enforced)
	}

	// Cross-domain merge: vol-1 must appear exactly once.
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 merged finding; got %d", len(report.Findings))
	}
	f := report.Findings[0]
	if f.ResourceID != "vol-1" {
		t.Errorf("ResourceID = %q; want vol-1", f.ResourceID)
	}
	// Highest severity across domains must win.
	if f.Severity != models.SeverityHigh {
		t.Errorf("Severity = %q; want HIGH (highest across domains)", f.Severity)
	}
	// Savings must be summed across domains.
	if f.EstimatedMonthlySavings != 5.0 {
		t.Errorf("EstimatedMonthlySavings = %.2f; want 5.00", f.EstimatedMonthlySavings)
	}
	// AuditType of the unified report must be "all".
	if report.AuditType != string(AuditTypeAll) {
		t.Errorf("AuditType = %q; want %q", report.AuditType, string(AuditTypeAll))
	}
}

// ── TestAuditAll_PolicyRespected ─────────────────────────────────────────────

// TestAuditAll_PolicyRespected verifies that per-domain policy enforcement is
// detected independently: only the domain that has a finding at or above the
// configured fail_on_severity threshold appears in the enforcedDomains slice.
func TestAuditAll_PolicyRespected(t *testing.T) {
	// Security domain has a CRITICAL finding; policy enforces at HIGH for security.
	secFindings := []models.Finding{
		newFinding("root-account", "global", "ROOT_ACCESS_KEY", models.SeverityCritical, 0.0),
	}
	policyCfg := &policy.PolicyConfig{
		Version: 1,
		Enforcement: map[string]policy.EnforcementConfig{
			"security": {FailOnSeverity: "HIGH"},
		},
	}

	eng := newAllAWSEngine(
		emptyDomainReport("cost", "test", "111122223333", []string{"us-east-1"}),
		domainReportWith("security", secFindings),
		emptyDomainReport("dataprotection", "test", "111122223333", []string{"us-east-1"}),
		policyCfg,
	)

	_, enforced, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the security domain must be flagged for enforcement.
	if len(enforced) != 1 || enforced[0] != "security" {
		t.Errorf("enforced = %v; want [security]", enforced)
	}
}

// ── TestAuditAll_SeverityOrdering ────────────────────────────────────────────

// TestAuditAll_SeverityOrdering verifies that merged findings from all three
// AWS domains are sorted globally: CRITICAL first, then HIGH, MEDIUM, LOW.
// It also checks that the unified report's summary counts are correct.
func TestAuditAll_SeverityOrdering(t *testing.T) {
	// Four findings across three AWS domains, each at a different severity level.
	// Security contributes two findings (HIGH + MEDIUM) to cover all four levels.
	costFindings := []models.Finding{
		newFinding("ec2-1", "us-east-1", "EC2_LOW_CPU", models.SeverityLow, 10.0),
	}
	secFindings := []models.Finding{
		newFinding("sg-1", "us-east-1", "SG_OPEN_SSH", models.SeverityHigh, 0.0),
		newFinding("alice", "us-east-1", "IAM_NO_MFA", models.SeverityMedium, 0.0),
	}
	dpFindings := []models.Finding{
		newFinding("rds-1", "us-east-1", "RDS_UNENCRYPTED", models.SeverityCritical, 0.0),
	}

	eng := newAllAWSEngine(
		domainReportWith("cost", costFindings),
		domainReportWith("security", secFindings),
		domainReportWith("dataprotection", dpFindings),
		nil,
	)

	report, _, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// All four findings must be present (no cross-domain deduplication here).
	if len(report.Findings) != 4 {
		t.Fatalf("expected 4 findings; got %d", len(report.Findings))
	}

	// Global sort: CRITICAL → HIGH → MEDIUM → LOW.
	wantOrder := []models.Severity{
		models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
	}
	for i, want := range wantOrder {
		if report.Findings[i].Severity != want {
			t.Errorf("findings[%d].Severity = %q; want %q",
				i, report.Findings[i].Severity, want)
		}
	}

	// Summary counts must reflect all four merged findings.
	s := report.Summary
	if s.TotalFindings != 4 {
		t.Errorf("Summary.TotalFindings = %d; want 4", s.TotalFindings)
	}
	if s.CriticalFindings != 1 {
		t.Errorf("Summary.CriticalFindings = %d; want 1", s.CriticalFindings)
	}
	if s.HighFindings != 1 {
		t.Errorf("Summary.HighFindings = %d; want 1", s.HighFindings)
	}
	if s.MediumFindings != 1 {
		t.Errorf("Summary.MediumFindings = %d; want 1", s.MediumFindings)
	}
	if s.LowFindings != 1 {
		t.Errorf("Summary.LowFindings = %d; want 1", s.LowFindings)
	}
}

// ── TestAuditAll_KubernetesNotInvoked ────────────────────────────────────────

// TestAuditAll_KubernetesNotInvoked asserts that AllAWSDomainsEngine operates
// exclusively with the three AWS domain engines and requires no Kubernetes
// provider. The absence of a kube field on AllAWSDomainsEngine enforces this at
// compile time; this test confirms the engine runs to completion without any
// kubeconfig access.
func TestAuditAll_KubernetesNotInvoked(t *testing.T) {
	// Construct the engine using struct literal — no kube field exists.
	eng := &AllAWSDomainsEngine{
		cost: &stubAWSEngine{
			report: emptyDomainReport("cost", "test", "111122223333", []string{"us-east-1"}),
		},
		sec: &stubAWSEngine{
			report: emptyDomainReport("security", "test", "111122223333", []string{"us-east-1"}),
		},
		dp: &stubAWSEngine{
			report: emptyDomainReport("dataprotection", "test", "111122223333", []string{"us-east-1"}),
		},
	}

	report, enforced, err := eng.RunAllAWSAudit(context.Background(), AllAWSAuditOptions{
		Profile: "test-profile",
		Regions: []string{"us-east-1"},
	})
	if err != nil {
		t.Fatalf("RunAllAWSAudit returned unexpected error: %v", err)
	}
	if len(enforced) != 0 {
		t.Errorf("expected no enforced domains; got %v", enforced)
	}
	if report.AuditType != string(AuditTypeAll) {
		t.Errorf("AuditType = %q; want %q", report.AuditType, string(AuditTypeAll))
	}
	// Verify no kubernetes resource types leaked into the report.
	for _, f := range report.Findings {
		rt := string(f.ResourceType)
		if len(rt) >= 3 && rt[:3] == "K8S" {
			t.Errorf("unexpected kubernetes finding in aws --all report: resource_type=%q", rt)
		}
	}
}
