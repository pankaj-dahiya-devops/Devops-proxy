package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/engine"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/policy"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/aws/common"
	awscost "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/aws/cost"
	awssecurity "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/aws/security"
	kube "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/kubernetes"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"
	costpack "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rulepacks/cost"
	dppack   "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rulepacks/dataprotection"
	secpack  "github.com/pankaj-dahiya-devops/Devops-proxy/internal/rulepacks/security"
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "dp",
		Short: "DevOps Proxy — extensible DevOps execution engine",
	}
	root.AddCommand(newAWSCmd())
	root.AddCommand(newKubernetesCmd())
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
	cmd.AddCommand(newSecurityCmd())
	cmd.AddCommand(newDataProtectionCmd())
	return cmd
}

// loadPolicyFile returns a PolicyConfig for the given path.
// If path is empty, it auto-discovers dp.yaml in the current directory.
// If neither is found, it returns nil (policy disabled — default behaviour).
func loadPolicyFile(path string) (*policy.PolicyConfig, error) {
	if path != "" {
		return policy.LoadPolicy(path)
	}
	if _, err := os.Stat("dp.yaml"); err == nil {
		return policy.LoadPolicy("dp.yaml")
	}
	return nil, nil
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
		policyPath  string
	)

	cmd := &cobra.Command{
		Use:   "cost",
		Short: "Audit AWS cost and identify wasted spend",
		RunE: func(cmd *cobra.Command, args []string) error {
			policyCfg, err := loadPolicyFile(policyPath)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}

			provider := common.NewDefaultAWSClientProvider()
			collector := awscost.NewDefaultCostCollector()

			registry := rules.NewDefaultRuleRegistry()
			for _, r := range costpack.New() {
				registry.Register(r)
			}

			eng := engine.NewAWSCostEngine(provider, collector, registry, policyCfg)

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
			} else if reportFmt == "json" {
				if err := printJSON(report); err != nil {
					return err
				}
			} else {
				printTable(report)
			}

			if policy.ShouldFail("cost", report.Findings, policyCfg) {
				return fmt.Errorf("policy enforcement triggered: findings at or above configured fail_on_severity")
			}
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
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists)")

	return cmd
}

func newSecurityCmd() *cobra.Command {
	var (
		profile     string
		allProfiles bool
		regions     []string
		reportFmt   string
		summary     bool
		output      string
		policyPath  string
	)

	cmd := &cobra.Command{
		Use:   "security",
		Short: "Audit AWS security posture: S3 public access, open SSH, IAM MFA, root access keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			policyCfg, err := loadPolicyFile(policyPath)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}

			provider := common.NewDefaultAWSClientProvider()
			collector := awssecurity.NewDefaultSecurityCollector()

			registry := rules.NewDefaultRuleRegistry()
			for _, r := range secpack.New() {
				registry.Register(r)
			}

			eng := engine.NewAWSSecurityEngine(provider, collector, registry, policyCfg)

			opts := engine.AuditOptions{
				AuditType:    engine.AuditTypeSecurity,
				Profile:      profile,
				AllProfiles:  allProfiles,
				Regions:      regions,
				ReportFormat: engine.ReportFormat(reportFmt),
			}

			report, err := eng.RunAudit(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("security audit failed: %w", err)
			}

			if output != "" {
				if err := writeReportToFile(output, report); err != nil {
					return err
				}
			}

			if summary {
				printSummary(os.Stdout, report)
			} else if reportFmt == "json" {
				if err := printJSON(report); err != nil {
					return err
				}
			} else {
				printSecurityTable(report)
			}

			if policy.ShouldFail("security", report.Findings, policyCfg) {
				return fmt.Errorf("policy enforcement triggered: findings at or above configured fail_on_severity")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS profile name (default: uses environment / default profile)")
	cmd.Flags().BoolVar(&allProfiles, "all-profiles", false, "Audit all configured AWS profiles")
	cmd.Flags().StringSliceVar(&regions, "region", nil, "AWS region(s) to audit (default: all active regions)")
	cmd.Flags().StringVar(&reportFmt, "report", "table", "Output format: json or table")
	cmd.Flags().BoolVar(&summary, "summary", false, "Print compact summary: totals, severity breakdown, top-5 findings")
	cmd.Flags().StringVar(&output, "output", "", "Write full JSON report to this file path (in addition to stdout output)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists)")

	return cmd
}

func newDataProtectionCmd() *cobra.Command {
	var (
		profile     string
		allProfiles bool
		regions     []string
		reportFmt   string
		summary     bool
		output      string
		policyPath  string
	)

	cmd := &cobra.Command{
		Use:   "dataprotection",
		Short: "Audit AWS data protection: EBS encryption, RDS encryption, S3 default encryption",
		RunE: func(cmd *cobra.Command, args []string) error {
			policyCfg, err := loadPolicyFile(policyPath)
			if err != nil {
				return fmt.Errorf("load policy: %w", err)
			}

			provider := common.NewDefaultAWSClientProvider()
			costCollector := awscost.NewDefaultCostCollector()
			secCollector := awssecurity.NewDefaultSecurityCollector()

			registry := rules.NewDefaultRuleRegistry()
			for _, r := range dppack.New() {
				registry.Register(r)
			}

			eng := engine.NewAWSDataProtectionEngine(provider, costCollector, secCollector, registry, policyCfg)

			opts := engine.AuditOptions{
				AuditType:    engine.AuditTypeDataProtection,
				Profile:      profile,
				AllProfiles:  allProfiles,
				Regions:      regions,
				ReportFormat: engine.ReportFormat(reportFmt),
			}

			report, err := eng.RunAudit(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("data protection audit failed: %w", err)
			}

			if output != "" {
				if err := writeReportToFile(output, report); err != nil {
					return err
				}
			}

			if summary {
				printSummary(os.Stdout, report)
			} else if reportFmt == "json" {
				if err := printJSON(report); err != nil {
					return err
				}
			} else {
				printDataProtectionTable(report)
			}

			if policy.ShouldFail("dataprotection", report.Findings, policyCfg) {
				return fmt.Errorf("policy enforcement triggered: findings at or above configured fail_on_severity")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "AWS profile name (default: uses environment / default profile)")
	cmd.Flags().BoolVar(&allProfiles, "all-profiles", false, "Audit all configured AWS profiles")
	cmd.Flags().StringSliceVar(&regions, "region", nil, "AWS region(s) to audit (default: all active regions)")
	cmd.Flags().StringVar(&reportFmt, "report", "table", "Output format: json or table")
	cmd.Flags().BoolVar(&summary, "summary", false, "Print compact summary: totals, severity breakdown, top-5 findings")
	cmd.Flags().StringVar(&output, "output", "", "Write full JSON report to this file path (in addition to stdout output)")
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists)")

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

// printDataProtectionTable renders the data-protection audit findings table.
// Like security findings, these have no estimated savings; the last column
// shows the resource type instead.
func printDataProtectionTable(report *models.AuditReport) {
	s := report.Summary
	fmt.Printf(
		"Profile: %-20s  Account: %-14s  Regions: %d  Findings: %d\n",
		report.Profile,
		report.AccountID,
		len(report.Regions),
		s.TotalFindings,
	)

	if len(report.Findings) == 0 {
		fmt.Println("No findings.")
		return
	}

	fmt.Println()
	fmt.Printf("%-42s  %-15s  %-10s  %s\n", "RESOURCE ID", "REGION", "SEVERITY", "TYPE")
	fmt.Println(strings.Repeat("-", 88))
	for _, f := range report.Findings {
		fmt.Printf("%-42s  %-15s  %-10s  %s\n",
			f.ResourceID,
			f.Region,
			string(f.Severity),
			string(f.ResourceType),
		)
	}
}

// ── kubernetes commands ───────────────────────────────────────────────────────

func newKubernetesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kubernetes",
		Short: "Kubernetes provider commands",
	}
	cmd.AddCommand(newInspectCmd())
	return cmd
}

func newInspectCmd() *cobra.Command {
	var contextName string

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect a Kubernetes cluster: context, API server, node count, namespace count",
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := kube.NewDefaultKubeClientProvider()
			return runKubernetesInspect(cmd.Context(), provider, contextName, os.Stdout)
		},
	}

	cmd.Flags().StringVar(&contextName, "context", "", "Kubeconfig context to use (default: current context)")

	return cmd
}

// runKubernetesInspect is the testable core of the inspect command.
// It accepts a KubeClientProvider so tests can inject a fake clientset.
func runKubernetesInspect(ctx context.Context, provider kube.KubeClientProvider, contextName string, w io.Writer) error {
	clientset, info, err := provider.ClientsetForContext(contextName)
	if err != nil {
		return fmt.Errorf("connect to cluster: %w", err)
	}

	data, err := kube.CollectClusterData(ctx, clientset, info)
	if err != nil {
		return fmt.Errorf("collect cluster data: %w", err)
	}

	printClusterInspect(w, data)
	return nil
}

// printClusterInspect writes the four-line cluster summary to w.
func printClusterInspect(w io.Writer, data *kube.ClusterData) {
	fmt.Fprintf(w, "Context:     %s\n", data.ClusterInfo.ContextName)
	fmt.Fprintf(w, "API Server:  %s\n", data.ClusterInfo.Server)
	fmt.Fprintf(w, "Nodes:       %d\n", len(data.Nodes))
	fmt.Fprintf(w, "Namespaces:  %d\n", len(data.Namespaces))
}

// ── AWS output renderers ──────────────────────────────────────────────────────

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

// printSecurityTable renders the security audit findings table.
// Security findings do not have estimated savings so the last column shows
// the resource type instead.
func printSecurityTable(report *models.AuditReport) {
	s := report.Summary
	fmt.Printf(
		"Profile: %-20s  Account: %-14s  Regions: %d  Findings: %d\n",
		report.Profile,
		report.AccountID,
		len(report.Regions),
		s.TotalFindings,
	)

	if len(report.Findings) == 0 {
		fmt.Println("No findings.")
		return
	}

	fmt.Println()
	fmt.Printf("%-42s  %-15s  %-10s  %s\n", "RESOURCE ID", "REGION", "SEVERITY", "TYPE")
	fmt.Println(strings.Repeat("-", 88))
	for _, f := range report.Findings {
		fmt.Printf("%-42s  %-15s  %-10s  %s\n",
			f.ResourceID,
			f.Region,
			string(f.Severity),
			string(f.ResourceType),
		)
	}
}
