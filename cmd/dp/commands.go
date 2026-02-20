package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/engine"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/aws/common"
	awscost "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/aws/cost"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "dp",
		Short: "DevOps Proxy — extensible DevOps execution engine",
	}
	root.AddCommand(newAWSCmd())
	return root
}

func newAWSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "AWS provider commands",
	}
	cmd.AddCommand(newAuditCmd())
	return cmd
}

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Run an audit against an AWS account",
	}
	cmd.AddCommand(newCostCmd())
	return cmd
}

func newCostCmd() *cobra.Command {
	var (
		profile     string
		allProfiles bool
		regions     []string
		days        int
		reportFmt   string
		summary     bool
		output      string
	)

	cmd := &cobra.Command{
		Use:   "cost",
		Short: "Audit AWS cost and identify wasted spend",
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := common.NewDefaultAWSClientProvider()
			collector := awscost.NewDefaultCostCollector()

			registry := rules.NewDefaultRuleRegistry()
			registry.Register(rules.EBSUnattachedRule{})
			registry.Register(rules.EBSGP2LegacyRule{})
			registry.Register(rules.EC2LowCPURule{})

			eng := engine.NewDefaultEngine(provider, collector, registry)

			opts := engine.AuditOptions{
				AuditType:    engine.AuditTypeCost,
				Profile:      profile,
				AllProfiles:  allProfiles,
				Regions:      regions,
				DaysBack:     days,
				ReportFormat: engine.ReportFormat(reportFmt),
			}

			report, err := eng.RunAudit(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("audit failed: %w", err)
			}

			if output != "" {
				if err := writeReportToFile(output, report); err != nil {
					return err
				}
			}

			if summary {
				printSummary(os.Stdout, report)
				return nil
			}
			if reportFmt == "json" {
				return printJSON(report)
			}
			printTable(report)
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS profile name (default: uses environment / default profile)")
	cmd.Flags().BoolVar(&allProfiles, "all-profiles", false, "Audit all configured AWS profiles")
	cmd.Flags().StringSliceVar(&regions, "region", nil, "AWS region(s) to audit (default: all active regions)")
	cmd.Flags().IntVar(&days, "days", 30, "Lookback window in days for cost and metric queries")
	cmd.Flags().StringVar(&reportFmt, "report", "table", "Output format: json or table")
	cmd.Flags().BoolVar(&summary, "summary", false, "Print compact summary: totals, severity breakdown, top-5 findings by savings")
	cmd.Flags().StringVar(&output, "output", "", "Write full JSON report to this file path (in addition to stdout output)")

	return cmd
}

// printJSON writes the report as indented JSON to stdout.
func printJSON(report *models.AuditReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// writeReportToFile serialises report as indented JSON and writes it to path,
// creating or overwriting the file. It does not affect stdout output.
func writeReportToFile(path string, report *models.AuditReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write report file %q: %w", path, err)
	}
	return nil
}

// printSummary renders a compact summary view to w:
//   - Account / profile / region header
//   - Total findings and total estimated monthly savings
//   - Per-severity finding counts
//   - Top 5 findings ranked by EstimatedMonthlySavings
//
// It reuses the already-computed AuditReport; no engine logic is duplicated.
func printSummary(w io.Writer, report *models.AuditReport) {
	s := report.Summary

	fmt.Fprintf(w, "Account:  %s\n", report.AccountID)
	fmt.Fprintf(w, "Profile:  %s\n", report.Profile)
	fmt.Fprintf(w, "Regions:  %d\n", len(report.Regions))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Total Findings:        %d\n", s.TotalFindings)
	fmt.Fprintf(w, "Est. Monthly Savings:  $%.2f\n", s.TotalEstimatedMonthlySavings)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Severity Breakdown")
	fmt.Fprintf(w, "  %-10s  %d\n", "CRITICAL", s.CriticalFindings)
	fmt.Fprintf(w, "  %-10s  %d\n", "HIGH", s.HighFindings)
	fmt.Fprintf(w, "  %-10s  %d\n", "MEDIUM", s.MediumFindings)
	fmt.Fprintf(w, "  %-10s  %d\n", "LOW", s.LowFindings)

	top := topFindingsBySavings(report.Findings, 5)
	if len(top) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Top Findings by Savings")
	fmt.Fprintf(w, "  %-42s  %-15s  %-10s  %s\n", "RESOURCE ID", "REGION", "SEVERITY", "SAVINGS/MO")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 82))
	for _, f := range top {
		fmt.Fprintf(w, "  %-42s  %-15s  %-10s  $%.2f\n",
			f.ResourceID, f.Region, string(f.Severity), f.EstimatedMonthlySavings)
	}
}

// topFindingsBySavings returns up to n findings from the provided slice,
// ordered by EstimatedMonthlySavings descending.
// The original slice is not modified.
func topFindingsBySavings(findings []models.Finding, n int) []models.Finding {
	sorted := make([]models.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].EstimatedMonthlySavings > sorted[j].EstimatedMonthlySavings
	})
	if n > len(sorted) {
		n = len(sorted)
	}
	return sorted[:n]
}

// printTable renders a human-readable summary followed by a findings table.
func printTable(report *models.AuditReport) {
	s := report.Summary
	fmt.Printf(
		"Profile: %-20s  Account: %-14s  Regions: %d  Findings: %d  Est. Savings: $%.2f/mo\n",
		report.Profile,
		report.AccountID,
		len(report.Regions),
		s.TotalFindings,
		s.TotalEstimatedMonthlySavings,
	)

	if len(report.Findings) == 0 {
		fmt.Println("No findings.")
		return
	}

	fmt.Println()
	fmt.Printf("%-42s  %-15s  %-10s  %s\n", "RESOURCE ID", "REGION", "SEVERITY", "SAVINGS/MO")
	fmt.Println(strings.Repeat("-", 82))
	for _, f := range report.Findings {
		fmt.Printf("%-42s  %-15s  %-10s  $%.2f\n",
			f.ResourceID,
			f.Region,
			string(f.Severity),
			f.EstimatedMonthlySavings,
		)
	}
}
