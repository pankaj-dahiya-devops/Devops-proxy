package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sclient "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	kube "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/kubernetes"
)

// ── kubernetes inspect test helpers ──────────────────────────────────────────

// testKubeProvider implements kube.KubeClientProvider backed by a pre-built
// fake clientset. It records the context name passed to ClientsetForContext so
// tests can assert the flag is forwarded correctly.
type testKubeProvider struct {
	clientset      k8sclient.Interface
	info           kube.ClusterInfo
	calledWithCtx  string
}

func (p *testKubeProvider) ClientsetForContext(contextName string) (k8sclient.Interface, kube.ClusterInfo, error) {
	p.calledWithCtx = contextName
	return p.clientset, p.info, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func makeReport(findings []models.Finding) *models.AuditReport {
	var s models.AuditSummary
	s.TotalFindings = len(findings)
	for _, f := range findings {
		s.TotalEstimatedMonthlySavings += f.EstimatedMonthlySavings
		switch f.Severity {
		case models.SeverityCritical:
			s.CriticalFindings++
		case models.SeverityHigh:
			s.HighFindings++
		case models.SeverityMedium:
			s.MediumFindings++
		case models.SeverityLow:
			s.LowFindings++
		}
	}
	return &models.AuditReport{
		ReportID:    "audit-test",
		GeneratedAt: time.Now().UTC(),
		AuditType:   "cost",
		Profile:     "staging",
		AccountID:   "111122223333",
		Regions:     []string{"us-east-1", "eu-west-1"},
		Summary:     s,
		Findings:    findings,
	}
}

func capture(fn func(w *bytes.Buffer)) string {
	var buf bytes.Buffer
	fn(&buf)
	return buf.String()
}

// ── printSummary ─────────────────────────────────────────────────────────────

func TestPrintSummary_Header(t *testing.T) {
	report := makeReport(nil)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	for _, want := range []string{"111122223333", "staging", "2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, out)
		}
	}
}

func TestPrintSummary_TotalsAndSavings(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "vol-1", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 8.00},
		{ResourceID: "vol-2", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 30.00},
		{ResourceID: "i-1", Region: "eu-west-1", Severity: models.SeverityHigh, EstimatedMonthlySavings: 50.00},
	}
	report := makeReport(findings)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	if !strings.Contains(out, "3") {
		t.Errorf("output missing total findings count 3\ngot:\n%s", out)
	}
	if !strings.Contains(out, "88.00") {
		t.Errorf("output missing total savings 88.00\ngot:\n%s", out)
	}
}

func TestPrintSummary_SeverityBreakdown(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "r-1", Severity: models.SeverityCritical, EstimatedMonthlySavings: 100},
		{ResourceID: "r-2", Severity: models.SeverityHigh, EstimatedMonthlySavings: 50},
		{ResourceID: "r-3", Severity: models.SeverityHigh, EstimatedMonthlySavings: 50},
		{ResourceID: "r-4", Severity: models.SeverityMedium, EstimatedMonthlySavings: 30},
		{ResourceID: "r-5", Severity: models.SeverityLow, EstimatedMonthlySavings: 8},
	}
	report := makeReport(findings)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	for _, label := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if !strings.Contains(out, label) {
			t.Errorf("output missing severity label %q\ngot:\n%s", label, out)
		}
	}
}

func TestPrintSummary_NoFindings_SkipsTopTable(t *testing.T) {
	report := makeReport(nil)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	if strings.Contains(out, "Top Findings") {
		t.Errorf("empty report must not print Top Findings section\ngot:\n%s", out)
	}
}

func TestPrintSummary_TopFindingsPresent(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "vol-cheap", Region: "us-east-1", Severity: models.SeverityLow, EstimatedMonthlySavings: 2.00},
		{ResourceID: "i-expensive", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 30.00},
		{ResourceID: "vol-mid", Region: "eu-west-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 8.00},
	}
	report := makeReport(findings)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	if !strings.Contains(out, "Top Findings") {
		t.Errorf("output missing Top Findings section\ngot:\n%s", out)
	}
	// Most expensive finding must appear; cheapest must also appear (only 3 findings < 5).
	if !strings.Contains(out, "i-expensive") {
		t.Errorf("output missing top-savings resource i-expensive\ngot:\n%s", out)
	}
	if !strings.Contains(out, "vol-cheap") {
		t.Errorf("output missing vol-cheap (fewer than 5 findings total)\ngot:\n%s", out)
	}
}

func TestPrintSummary_TopFindingsCappedAtFive(t *testing.T) {
	findings := make([]models.Finding, 8)
	for i := range findings {
		findings[i] = models.Finding{
			ResourceID:              fmt.Sprintf("vol-%02d", i),
			Region:                  "us-east-1",
			Severity:                models.SeverityLow,
			EstimatedMonthlySavings: float64(i + 1),
		}
	}
	report := makeReport(findings)
	out := capture(func(w *bytes.Buffer) { printSummary(w, report) })

	// The 3 lowest-savings resources (vol-00, vol-01, vol-02) must NOT appear.
	for _, absent := range []string{"vol-00", "vol-01", "vol-02"} {
		if strings.Contains(out, absent) {
			t.Errorf("output must not contain %q (outside top-5)\ngot:\n%s", absent, out)
		}
	}
	// Top resource by savings is vol-07 (savings=8).
	if !strings.Contains(out, "vol-07") {
		t.Errorf("output missing highest-savings resource vol-07\ngot:\n%s", out)
	}
}

// ── topFindingsBySavings ─────────────────────────────────────────────────────

func TestTopFindingsBySavings_Empty(t *testing.T) {
	got := topFindingsBySavings(nil, 5)
	if len(got) != 0 {
		t.Errorf("want 0, got %d", len(got))
	}
}

func TestTopFindingsBySavings_FewerThanN(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "a", EstimatedMonthlySavings: 10},
		{ResourceID: "b", EstimatedMonthlySavings: 5},
	}
	got := topFindingsBySavings(findings, 5)
	if len(got) != 2 {
		t.Errorf("want 2, got %d", len(got))
	}
}

func TestTopFindingsBySavings_ReturnsTopN(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "low", EstimatedMonthlySavings: 1},
		{ResourceID: "high", EstimatedMonthlySavings: 100},
		{ResourceID: "mid", EstimatedMonthlySavings: 50},
		{ResourceID: "mid2", EstimatedMonthlySavings: 30},
	}
	got := topFindingsBySavings(findings, 2)
	if len(got) != 2 {
		t.Fatalf("want 2, got %d", len(got))
	}
	if got[0].ResourceID != "high" {
		t.Errorf("position 0: got %q; want high", got[0].ResourceID)
	}
	if got[1].ResourceID != "mid" {
		t.Errorf("position 1: got %q; want mid", got[1].ResourceID)
	}
}

func TestTopFindingsBySavings_SortedDescending(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "a", EstimatedMonthlySavings: 5},
		{ResourceID: "b", EstimatedMonthlySavings: 50},
		{ResourceID: "c", EstimatedMonthlySavings: 20},
		{ResourceID: "d", EstimatedMonthlySavings: 80},
		{ResourceID: "e", EstimatedMonthlySavings: 10},
	}
	got := topFindingsBySavings(findings, 5)
	for i := 1; i < len(got); i++ {
		if got[i].EstimatedMonthlySavings > got[i-1].EstimatedMonthlySavings {
			t.Errorf("not sorted desc at position %d: %.2f > %.2f",
				i, got[i].EstimatedMonthlySavings, got[i-1].EstimatedMonthlySavings)
		}
	}
}

func TestTopFindingsBySavings_DoesNotMutateInput(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "a", EstimatedMonthlySavings: 1},
		{ResourceID: "b", EstimatedMonthlySavings: 100},
	}
	topFindingsBySavings(findings, 2)
	// Original order must be preserved.
	if findings[0].ResourceID != "a" || findings[1].ResourceID != "b" {
		t.Error("topFindingsBySavings must not modify the input slice")
	}
}

// ── writeReportToFile ─────────────────────────────────────────────────────────

func TestWriteReportToFile_Success(t *testing.T) {
	report := makeReport(nil)
	path := filepath.Join(t.TempDir(), "report.json")

	if err := writeReportToFile(path, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestWriteReportToFile_InvalidPath(t *testing.T) {
	report := makeReport(nil)
	// Directory does not exist — write must fail.
	path := filepath.Join(t.TempDir(), "nonexistent", "report.json")

	if err := writeReportToFile(path, report); err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

func TestWriteReportToFile_ContentMatchesJSON(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "vol-abc", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 16.00},
	}
	report := makeReport(findings)
	path := filepath.Join(t.TempDir(), "report.json")

	if err := writeReportToFile(path, report); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	var got models.AuditReport
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.AccountID != report.AccountID {
		t.Errorf("account_id: got %q; want %q", got.AccountID, report.AccountID)
	}
	if got.Profile != report.Profile {
		t.Errorf("profile: got %q; want %q", got.Profile, report.Profile)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings count: got %d; want 1", len(got.Findings))
	}
	if got.Findings[0].ResourceID != "vol-abc" {
		t.Errorf("finding resource_id: got %q; want vol-abc", got.Findings[0].ResourceID)
	}
	if got.Summary.TotalEstimatedMonthlySavings != 16.00 {
		t.Errorf("savings: got %.2f; want 16.00", got.Summary.TotalEstimatedMonthlySavings)
	}
}

// ── runKubernetesInspect ──────────────────────────────────────────────────────

// TestRunKubernetesInspect_Output verifies that all four fields (Context,
// API Server, Nodes, Namespaces) appear in the output with the correct values.
func TestRunKubernetesInspect_Output(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-1"}},
		&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-2"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "staging"}},
	)
	provider := &testKubeProvider{
		clientset: fakeClient,
		info:      kube.ClusterInfo{ContextName: "dev-cluster", Server: "https://192.168.1.100:6443"},
	}

	var buf bytes.Buffer
	if err := runKubernetesInspect(context.Background(), provider, "", &buf); err != nil {
		t.Fatalf("runKubernetesInspect error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"dev-cluster",
		"https://192.168.1.100:6443",
		"2",  // node count
		"3",  // namespace count
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, out)
		}
	}
}

// ── newKubernetesAuditCmd flags ───────────────────────────────────────────────

// TestKubernetesAuditCmd_ExcludeSystemFlag_Registered verifies that the
// --exclude-system flag is declared on the kubernetes audit command with the
// correct default value (false).
func TestKubernetesAuditCmd_ExcludeSystemFlag_Registered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("exclude-system")
	if flag == nil {
		t.Fatal("--exclude-system flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "false" {
		t.Errorf("--exclude-system default = %q; want false", flag.DefValue)
	}
}

// TestKubernetesAuditCmd_ExcludeSystemFlag_Type verifies the flag is a bool.
func TestKubernetesAuditCmd_ExcludeSystemFlag_Type(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("exclude-system")
	if flag == nil {
		t.Fatal("--exclude-system flag not registered")
	}
	if flag.Value.Type() != "bool" {
		t.Errorf("--exclude-system flag type = %q; want bool", flag.Value.Type())
	}
}

// TestRunKubernetesInspect_ContextForwarded verifies that the --context flag
// value is passed through to the KubeClientProvider unchanged.
func TestRunKubernetesInspect_ContextForwarded(t *testing.T) {
	provider := &testKubeProvider{
		clientset: fake.NewSimpleClientset(),
		info:      kube.ClusterInfo{},
	}

	var buf bytes.Buffer
	if err := runKubernetesInspect(context.Background(), provider, "my-context", &buf); err != nil {
		t.Fatalf("runKubernetesInspect error: %v", err)
	}

	if provider.calledWithCtx != "my-context" {
		t.Errorf("provider called with context %q; want my-context", provider.calledWithCtx)
	}
}

// ── renderKubernetesAuditOutput ───────────────────────────────────────────────

// TestRenderKubernetesAuditOutput_JSONMode_PureJSON verifies that in JSON mode
// stdout begins with '{' and does not contain any banner lines.
func TestRenderKubernetesAuditOutput_JSONMode_PureJSON(t *testing.T) {
	report := makeReport([]models.Finding{
		{ResourceID: "pod-1", Severity: models.SeverityCritical},
	})
	report.Profile = "my-cluster"

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "json", false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON output must start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Context:", "Profile:", "Findings:"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain %q; got non-empty match", banned)
		}
	}
}

// TestRenderKubernetesAuditOutput_JSONMode_SummaryIgnored verifies that JSON
// mode takes priority over --summary: output must still be pure JSON.
func TestRenderKubernetesAuditOutput_JSONMode_SummaryIgnored(t *testing.T) {
	report := makeReport(nil)
	report.Profile = "my-cluster"

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "json", true, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON mode with summary=true must still start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Context:", "Profile:", "Findings:", "CRITICAL", "Severity"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain human-readable banner %q", banned)
		}
	}
}

// TestRenderKubernetesAuditOutput_JSONMode_IsValidJSON verifies the output
// parses cleanly as an AuditReport.
func TestRenderKubernetesAuditOutput_JSONMode_IsValidJSON(t *testing.T) {
	report := makeReport([]models.Finding{
		{ResourceID: "pod-1", Severity: models.SeverityHigh},
	})

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "json", false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}
}

// TestRenderKubernetesAuditOutput_TableMode_ContextPresent verifies that in
// table mode the "Context:" banner is written to the output.
func TestRenderKubernetesAuditOutput_TableMode_ContextPresent(t *testing.T) {
	report := makeReport(nil)
	report.Profile = "prod-cluster"

	var buf bytes.Buffer
	if err := renderKubernetesAuditOutput(&buf, report, "table", false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Context:") {
		t.Errorf("table output must contain 'Context:'; got:\n%s", out)
	}
	if !strings.Contains(out, "prod-cluster") {
		t.Errorf("table output must contain cluster name; got:\n%s", out)
	}
}

// ── renderAWSCostOutput ───────────────────────────────────────────────────────

// TestRenderAWSCostOutput_JSONMode_PureJSON verifies that JSON mode produces
// no banner lines — only the JSON payload.
func TestRenderAWSCostOutput_JSONMode_PureJSON(t *testing.T) {
	report := makeReport([]models.Finding{
		{ResourceID: "vol-1", Region: "us-east-1", Severity: models.SeverityHigh},
	})

	var buf bytes.Buffer
	if err := renderAWSCostOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON output must start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Profile:", "Findings:", "Savings"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain banner text %q", banned)
		}
	}
}

// TestRenderAWSCostOutput_JSONMode_SummaryIgnored verifies that JSON mode takes
// priority when --summary is also set.
func TestRenderAWSCostOutput_JSONMode_SummaryIgnored(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSCostOutput(&buf, report, "json", true, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON mode with summary=true must still start with '{'; got: %.40s", out)
	}
}

// TestRenderAWSCostOutput_JSONMode_IsValidJSON verifies the output is parseable.
func TestRenderAWSCostOutput_JSONMode_IsValidJSON(t *testing.T) {
	report := makeReport([]models.Finding{
		{ResourceID: "vol-1", Region: "us-east-1", Severity: models.SeverityMedium, EstimatedMonthlySavings: 8.0},
	})

	var buf bytes.Buffer
	if err := renderAWSCostOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\ngot:\n%s", err, buf.String())
	}
	if len(got.Findings) != 1 || got.Findings[0].ResourceID != "vol-1" {
		t.Errorf("findings not preserved in JSON; got: %+v", got.Findings)
	}
}

// TestRenderAWSCostOutput_TableMode_ProfilePresent verifies that in table mode
// the "Profile:" banner is written to the output.
func TestRenderAWSCostOutput_TableMode_ProfilePresent(t *testing.T) {
	report := makeReport(nil)
	// report.Profile is set by makeReport to "staging"

	var buf bytes.Buffer
	if err := renderAWSCostOutput(&buf, report, "table", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Profile:") {
		t.Errorf("table output must contain 'Profile:'; got:\n%s", out)
	}
	if !strings.Contains(out, "staging") {
		t.Errorf("table output must contain profile name; got:\n%s", out)
	}
}

// ── renderAWSSecurityOutput ───────────────────────────────────────────────────

// TestRenderAWSSecurityOutput_JSONMode_PureJSON verifies that JSON mode for
// the security command produces no banner text.
func TestRenderAWSSecurityOutput_JSONMode_PureJSON(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSSecurityOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON output must start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Profile:", "Findings:"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain banner text %q", banned)
		}
	}
}

// TestRenderAWSSecurityOutput_JSONMode_SummaryIgnored verifies JSON takes priority.
func TestRenderAWSSecurityOutput_JSONMode_SummaryIgnored(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSSecurityOutput(&buf, report, "json", true, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Errorf("JSON mode with summary=true must still start with '{'")
	}
}

// ── renderAWSDataProtectionOutput ────────────────────────────────────────────

// TestRenderAWSDataProtectionOutput_JSONMode_PureJSON verifies that JSON mode
// for the data-protection command produces no banner text.
func TestRenderAWSDataProtectionOutput_JSONMode_PureJSON(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSDataProtectionOutput(&buf, report, "json", false, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("JSON output must start with '{'; got: %.40s", out)
	}
	for _, banned := range []string{"Profile:", "Findings:"} {
		if strings.Contains(out, banned) {
			t.Errorf("JSON output must not contain banner text %q", banned)
		}
	}
}

// TestRenderAWSDataProtectionOutput_JSONMode_SummaryIgnored verifies JSON priority.
func TestRenderAWSDataProtectionOutput_JSONMode_SummaryIgnored(t *testing.T) {
	report := makeReport(nil)

	var buf bytes.Buffer
	if err := renderAWSDataProtectionOutput(&buf, report, "json", true, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "{") {
		t.Errorf("JSON mode with summary=true must still start with '{'")
	}
}

// ── hasCriticalOrHighFindings ─────────────────────────────────────────────────

// TestHasCriticalOrHighFindings_NilFindings verifies that nil input returns false.
func TestHasCriticalOrHighFindings_NilFindings(t *testing.T) {
	if hasCriticalOrHighFindings(nil) {
		t.Error("hasCriticalOrHighFindings(nil) = true; want false")
	}
}

// TestHasCriticalOrHighFindings_EmptySlice verifies that an empty slice returns false.
func TestHasCriticalOrHighFindings_EmptySlice(t *testing.T) {
	if hasCriticalOrHighFindings([]models.Finding{}) {
		t.Error("hasCriticalOrHighFindings([]) = true; want false")
	}
}

// TestHasCriticalOrHighFindings_OnlyLowMedium verifies that only LOW/MEDIUM
// findings return false (exit code 0 — no alert).
func TestHasCriticalOrHighFindings_OnlyLowMedium(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "r-1", Severity: models.SeverityLow},
		{ResourceID: "r-2", Severity: models.SeverityMedium},
	}
	if hasCriticalOrHighFindings(findings) {
		t.Error("hasCriticalOrHighFindings(LOW+MEDIUM only) = true; want false")
	}
}

// TestHasCriticalOrHighFindings_CriticalPresent verifies that a CRITICAL finding
// returns true — the exit-code-1 path must trigger.
func TestHasCriticalOrHighFindings_CriticalPresent(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "r-1", Severity: models.SeverityMedium},
		{ResourceID: "r-2", Severity: models.SeverityCritical},
	}
	if !hasCriticalOrHighFindings(findings) {
		t.Error("hasCriticalOrHighFindings with CRITICAL = false; want true")
	}
}

// TestHasCriticalOrHighFindings_HighPresent verifies that a HIGH finding
// returns true — the exit-code-1 path must trigger.
func TestHasCriticalOrHighFindings_HighPresent(t *testing.T) {
	findings := []models.Finding{
		{ResourceID: "r-1", Severity: models.SeverityLow},
		{ResourceID: "r-2", Severity: models.SeverityHigh},
	}
	if !hasCriticalOrHighFindings(findings) {
		t.Error("hasCriticalOrHighFindings with HIGH = false; want true")
	}
}

// ── --output / --file flag registration ──────────────────────────────────────
// These tests verify that every audit command declares --output (format, default
// "table") and --file (file path, default "") flags consistently.

// TestCostCmd_OutputFlagRegistered verifies --output flag on dp aws audit cost.
func TestCostCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newCostCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on cost command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestCostCmd_FileFlagRegistered verifies --file flag on dp aws audit cost.
func TestCostCmd_FileFlagRegistered(t *testing.T) {
	cmd := newCostCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on cost command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}

// TestSecurityCmd_OutputFlagRegistered verifies --output flag on dp aws audit security.
func TestSecurityCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newSecurityCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on security command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestSecurityCmd_FileFlagRegistered verifies --file flag on dp aws audit security.
func TestSecurityCmd_FileFlagRegistered(t *testing.T) {
	cmd := newSecurityCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on security command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}

// TestDataProtectionCmd_OutputFlagRegistered verifies --output flag on dp aws audit dataprotection.
func TestDataProtectionCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newDataProtectionCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on dataprotection command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestDataProtectionCmd_FileFlagRegistered verifies --file flag on dp aws audit dataprotection.
func TestDataProtectionCmd_FileFlagRegistered(t *testing.T) {
	cmd := newDataProtectionCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on dataprotection command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}

// TestKubernetesAuditCmd_OutputFlagRegistered verifies --output flag on dp kubernetes audit.
func TestKubernetesAuditCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestKubernetesAuditCmd_FileFlagRegistered verifies --file flag on dp kubernetes audit.
func TestKubernetesAuditCmd_FileFlagRegistered(t *testing.T) {
	cmd := newKubernetesAuditCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on kubernetes audit command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}

// TestAuditAllCmd_OutputFlagRegistered verifies --output flag on dp aws audit --all.
func TestAuditAllCmd_OutputFlagRegistered(t *testing.T) {
	cmd := newAuditCmd()
	flag := cmd.Flags().Lookup("output")
	if flag == nil {
		t.Fatal("--output flag not registered on aws audit command")
	}
	if flag.DefValue != "table" {
		t.Errorf("--output default = %q; want table", flag.DefValue)
	}
}

// TestAuditAllCmd_FileFlagRegistered verifies --file flag on dp aws audit --all.
func TestAuditAllCmd_FileFlagRegistered(t *testing.T) {
	cmd := newAuditCmd()
	flag := cmd.Flags().Lookup("file")
	if flag == nil {
		t.Fatal("--file flag not registered on aws audit command")
	}
	if flag.DefValue != "" {
		t.Errorf("--file default = %q; want empty string", flag.DefValue)
	}
}
