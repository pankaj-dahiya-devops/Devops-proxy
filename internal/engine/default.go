package engine

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/aws/common"
	awscost "github.com/pankaj-dahiya-devops/Devops-proxy/internal/providers/aws/cost"
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/rules"
)

// DefaultEngine is the production implementation of Engine.
// It coordinates data collection, rule evaluation, and report assembly.
// It never calls the AWS SDK, LLM, or any external service directly.
type DefaultEngine struct {
	provider common.AWSClientProvider
	cost     awscost.CostCollector
	registry rules.RuleRegistry
}

// NewDefaultEngine constructs a DefaultEngine wired to the supplied provider,
// cost collector, and rule registry.
func NewDefaultEngine(
	provider common.AWSClientProvider,
	costCollector awscost.CostCollector,
	registry rules.RuleRegistry,
) *DefaultEngine {
	return &DefaultEngine{
		provider: provider,
		cost:     costCollector,
		registry: registry,
	}
}

// RunAudit implements Engine. Only AuditTypeCost is supported in the MVP.
// It loads the requested AWS profile(s), discovers regions if not explicitly
// provided, collects cost data, evaluates all registered rules, and returns a
// fully populated AuditReport.
func (e *DefaultEngine) RunAudit(ctx context.Context, opts AuditOptions) (*models.AuditReport, error) {
	if opts.AuditType != AuditTypeCost {
		return nil, fmt.Errorf("unsupported audit type: %q", opts.AuditType)
	}

	daysBack := opts.DaysBack
	if daysBack <= 0 {
		daysBack = 30
	}

	if opts.AllProfiles {
		return e.runAllProfiles(ctx, opts, daysBack)
	}
	return e.runSingleProfile(ctx, opts, daysBack)
}

// runSingleProfile executes a cost audit for one AWS profile and returns the
// resulting report.
func (e *DefaultEngine) runSingleProfile(
	ctx context.Context,
	opts AuditOptions,
	daysBack int,
) (*models.AuditReport, error) {
	profile, err := e.provider.LoadProfile(ctx, opts.Profile)
	if err != nil {
		return nil, fmt.Errorf("load profile %q: %w", opts.Profile, err)
	}

	regions, err := e.resolveRegions(ctx, profile, opts.Regions)
	if err != nil {
		return nil, fmt.Errorf("resolve regions for profile %q: %w", profile.ProfileName, err)
	}

	regionData, costSummary, err := e.cost.CollectAll(ctx, profile, e.provider, regions, daysBack)
	if err != nil {
		return nil, fmt.Errorf("collect data for profile %q: %w", profile.ProfileName, err)
	}

	findings := e.evaluateAll(regionData, costSummary, profile.AccountID, profile.ProfileName)
	return buildReport(profile.ProfileName, profile.AccountID, regions, findings, costSummary), nil
}

// runAllProfiles loads every configured AWS profile, audits each one, and
// merges all findings into a single report. The report-level Profile field is
// set to "multi"; each individual Finding carries its own Profile and AccountID.
// Profile failures are skipped non-fatally; an error is returned only when no
// profile can be audited at all.
func (e *DefaultEngine) runAllProfiles(
	ctx context.Context,
	opts AuditOptions,
	daysBack int,
) (*models.AuditReport, error) {
	profiles, err := e.provider.LoadAllProfiles(ctx)
	if err != nil {
		return nil, fmt.Errorf("load all profiles: %w", err)
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("no AWS profiles found")
	}

	var (
		allFindings     []models.Finding
		allRegions      []string
		seenRegions     = make(map[string]struct{})
		lastCostSummary *models.CostSummary
		audited         int
	)

	for _, profile := range profiles {
		regions, err := e.resolveRegions(ctx, profile, opts.Regions)
		if err != nil {
			continue // skip this profile; others may succeed
		}

		regionData, costSummary, err := e.cost.CollectAll(ctx, profile, e.provider, regions, daysBack)
		if err != nil {
			continue
		}
		audited++

		findings := e.evaluateAll(regionData, costSummary, profile.AccountID, profile.ProfileName)
		allFindings = append(allFindings, findings...)

		for _, r := range regions {
			if _, seen := seenRegions[r]; !seen {
				seenRegions[r] = struct{}{}
				allRegions = append(allRegions, r)
			}
		}
		if costSummary != nil {
			lastCostSummary = costSummary
		}
	}

	if audited == 0 {
		return nil, fmt.Errorf("all profiles failed; no data collected")
	}

	return buildReport("multi", "", allRegions, allFindings, lastCostSummary), nil
}

// resolveRegions returns the explicit region list when provided, otherwise
// calls GetActiveRegions to discover opted-in regions for the profile.
func (e *DefaultEngine) resolveRegions(
	ctx context.Context,
	profile *common.ProfileConfig,
	explicit []string,
) ([]string, error) {
	if len(explicit) > 0 {
		return explicit, nil
	}
	return e.provider.GetActiveRegions(ctx, profile)
}

// evaluateAll applies every registered rule to each region's collected data
// and returns the merged findings slice.
func (e *DefaultEngine) evaluateAll(
	regionData []models.RegionData,
	costSummary *models.CostSummary,
	accountID, profile string,
) []models.Finding {
	var findings []models.Finding
	for i := range regionData {
		rctx := rules.RuleContext{
			AccountID:   accountID,
			Profile:     profile,
			RegionData:  &regionData[i],
			CostSummary: costSummary,
		}
		findings = append(findings, e.registry.EvaluateAll(rctx)...)
	}
	return findings
}

// buildReport assembles the final AuditReport from collected data and findings.
// Raw findings are first merged per resource (same ResourceID+Region), then
// sorted: CRITICAL → HIGH → MEDIUM → LOW → INFO, ties broken by
// EstimatedMonthlySavings descending.
func buildReport(
	profile, accountID string,
	regions []string,
	findings []models.Finding,
	costSummary *models.CostSummary,
) *models.AuditReport {
	merged := mergeFindings(findings)
	sortFindings(merged)
	return &models.AuditReport{
		ReportID:    fmt.Sprintf("audit-%d", time.Now().UnixNano()),
		GeneratedAt: time.Now().UTC(),
		AuditType:   string(AuditTypeCost),
		Profile:     profile,
		AccountID:   accountID,
		Regions:     regions,
		Summary:     computeSummary(merged),
		Findings:    merged,
		CostSummary: costSummary,
	}
}

// findingGroupKey is the composite key used to group findings by resource.
type findingGroupKey struct {
	resourceID string
	region     string
}

// mergeFindings collapses findings that refer to the same resource
// (same ResourceID + Region) into a single Finding:
//   - Severity: highest (lowest severityRank) across the group
//   - EstimatedMonthlySavings: sum across the group
//   - Metadata["rules"]: []string of every RuleID that fired on this resource
//
// All other fields (ID, RuleID, ResourceType, Explanation, Recommendation,
// DetectedAt, AccountID, Profile) are taken from the first finding in the group.
// Additional Metadata keys from later findings are merged in without overwriting
// keys already set by earlier findings.
// Insertion order of groups is preserved so sortFindings controls final order.
func mergeFindings(raw []models.Finding) []models.Finding {
	type entry struct {
		f       models.Finding
		ruleIDs []string
	}

	index := make(map[findingGroupKey]int) // key → position in entries
	var order []findingGroupKey
	entries := make([]entry, 0, len(raw))

	for _, f := range raw {
		key := findingGroupKey{resourceID: f.ResourceID, region: f.Region}
		pos, exists := index[key]
		if !exists {
			// First finding for this resource — clone metadata map and use as base.
			meta := make(map[string]any, len(f.Metadata)+1)
			for k, v := range f.Metadata {
				meta[k] = v
			}
			f.Metadata = meta
			entries = append(entries, entry{f: f, ruleIDs: []string{f.RuleID}})
			index[key] = len(entries) - 1
			order = append(order, key)
			continue
		}

		e := &entries[pos]
		e.ruleIDs = append(e.ruleIDs, f.RuleID)

		// Upgrade severity if this finding is more severe.
		if severityRank[f.Severity] < severityRank[e.f.Severity] {
			e.f.Severity = f.Severity
		}

		// Accumulate estimated savings.
		e.f.EstimatedMonthlySavings += f.EstimatedMonthlySavings

		// Merge any new metadata keys from this finding; do not overwrite existing.
		for k, v := range f.Metadata {
			if _, alreadySet := e.f.Metadata[k]; !alreadySet {
				e.f.Metadata[k] = v
			}
		}
	}

	// Stamp Metadata["rules"] and collect results in group-insertion order.
	result := make([]models.Finding, 0, len(entries))
	for _, key := range order {
		e := &entries[index[key]]
		e.f.Metadata["rules"] = e.ruleIDs
		result = append(result, e.f)
	}
	return result
}

// severityRank maps Severity values to sort keys (lower = higher priority).
var severityRank = map[models.Severity]int{
	models.SeverityCritical: 0,
	models.SeverityHigh:     1,
	models.SeverityMedium:   2,
	models.SeverityLow:      3,
	models.SeverityInfo:     4,
}

// sortFindings sorts findings in-place: severity descending (CRITICAL first),
// then EstimatedMonthlySavings descending within the same severity.
func sortFindings(findings []models.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri := severityRank[findings[i].Severity]
		rj := severityRank[findings[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return findings[i].EstimatedMonthlySavings > findings[j].EstimatedMonthlySavings
	})
}

// computeSummary aggregates finding counts and total estimated savings across
// all severity levels.
func computeSummary(findings []models.Finding) models.AuditSummary {
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
	return s
}
