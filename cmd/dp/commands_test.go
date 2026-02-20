package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

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
