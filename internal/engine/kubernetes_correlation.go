package engine

import (
	"github.com/pankaj-dahiya-devops/Devops-proxy/internal/models"
)

// ruleIDsForFinding returns all rule IDs associated with a finding.
// When multiple rules were merged by mergeFindings, the merged rule IDs are
// stored in Metadata["rules"]; these are included alongside the primary RuleID.
func ruleIDsForFinding(f *models.Finding) []string {
	ids := []string{f.RuleID}
	if f.Metadata != nil {
		if rr, ok := f.Metadata["rules"]; ok {
			if merged, ok := rr.([]string); ok {
				ids = append(ids, merged...)
			}
		}
	}
	return ids
}

// idsContain reports whether any element of ids equals target.
func idsContain(ids []string, target string) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

// nsIndexHas reports whether the namespace rule index entry for ns contains ruleID.
func nsIndexHas(index map[string]map[string]struct{}, ns, ruleID string) bool {
	if rules, ok := index[ns]; ok {
		_, found := rules[ruleID]
		return found
	}
	return false
}

// buildNamespaceRuleIndex constructs a map of namespace → set of rule IDs that
// have findings in that namespace. Used by the correlation pass to detect
// compound risk patterns across multiple findings in the same namespace.
//
// Only namespace-scoped findings contribute to the index; cluster-scoped
// findings (resolveNamespaceForFinding returns "") are skipped.
func buildNamespaceRuleIndex(findings []models.Finding) map[string]map[string]struct{} {
	index := make(map[string]map[string]struct{})
	for i := range findings {
		f := &findings[i]
		ns := resolveNamespaceForFinding(f)
		if ns == "" {
			continue
		}
		if index[ns] == nil {
			index[ns] = make(map[string]struct{})
		}
		for _, id := range ruleIDsForFinding(f) {
			index[ns][id] = struct{}{}
		}
	}
	return index
}

// filterByMinRiskScore returns a new slice containing only findings whose
// risk_chain_score is >= min. Findings with no chain score (score == 0) are
// excluded when min > 0. The original slice is not modified.
//
// This filter is applied after correlateRiskChains and after the maxRiskScore
// computation so that Summary.RiskScore reflects the full pre-filter picture.
func filterByMinRiskScore(findings []models.Finding, min int) []models.Finding {
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if getRiskScore(f) >= min {
			out = append(out, f)
		}
	}
	return out
}

// getRiskScore returns the risk_chain_score stored in f.Metadata, or 0 if the
// key is absent or not an int. Used to compute the report-level summary score.
func getRiskScore(f models.Finding) int {
	if f.Metadata == nil {
		return 0
	}
	if score, ok := f.Metadata["risk_chain_score"].(int); ok {
		return score
	}
	return 0
}

// correlateRiskChains annotates findings that participate in compound risk
// patterns with Metadata["risk_chain_score"] (int) and
// Metadata["risk_chain_reason"] (string).
//
// Six risk chains are detected:
//
//	Chain 1 (score 80): A public LoadBalancer service
//	  (K8S_SERVICE_PUBLIC_LOADBALANCER) and a pod with K8S_POD_RUN_AS_ROOT or
//	  K8S_POD_CAP_SYS_ADMIN co-exist in the same namespace.
//	  Reason: "Public service exposes privileged workload"
//
//	Chain 2 (score 60): A pod uses the default ServiceAccount
//	  (K8S_DEFAULT_SERVICEACCOUNT_USED) and the default ServiceAccount has
//	  automount enabled (K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT) in the same namespace.
//	  Reason: "Default service account with auto-mounted token"
//
//	Chain 3 (score 50): The cluster has a single node (K8S_CLUSTER_SINGLE_NODE)
//	  and at least one CRITICAL severity finding exists.
//	  Reason: "Single-node cluster with critical pod security violation"
//
//	Chain 4 (score 90): EKS node group IAM role is overpermissive
//	  (EKS_NODE_ROLE_OVERPERMISSIVE) and a public LoadBalancer service exists
//	  (K8S_SERVICE_PUBLIC_LOADBALANCER) anywhere in the cluster.
//	  Reason: "Public service exposed in cluster with over-permissive node IAM role."
//
//	Chain 5 (score 85): A ServiceAccount lacks IRSA annotation
//	  (EKS_SERVICEACCOUNT_NO_IRSA) and the default ServiceAccount is used
//	  (K8S_DEFAULT_SERVICEACCOUNT_USED) in the same namespace.
//	  Reason: "Default service account used without IRSA."
//
//	Chain 6 (score 95): The cluster lacks an IAM OIDC provider
//	  (EKS_OIDC_PROVIDER_NOT_ASSOCIATED) and at least one HIGH severity finding
//	  exists in the cluster.
//	  Reason: "Cluster lacks OIDC provider and has high-risk workload findings."
//
// When multiple chains apply to the same finding, the highest score is kept.
// Severity and sort order are not affected.
//
// Must be called after mergeFindings, annotateNamespaceType, and (optionally)
// excludeSystemFindings so that the correlation operates on the final finding set.
func correlateRiskChains(findings []models.Finding) {
	if len(findings) == 0 {
		return
	}

	// ── Phase 1: build lookup structures ──────────────────────────────────────

	nsIndex := buildNamespaceRuleIndex(findings)

	hasSingleNode := false
	hasCritical := false
	hasNodeRoleOverpermissive := false
	hasPublicLB := false
	hasOIDCNotAssociated := false
	hasHighSeverity := false

	for i := range findings {
		f := &findings[i]
		ids := ruleIDsForFinding(f)
		if idsContain(ids, "K8S_CLUSTER_SINGLE_NODE") {
			hasSingleNode = true
		}
		if f.Severity == models.SeverityCritical {
			hasCritical = true
		}
		if idsContain(ids, "EKS_NODE_ROLE_OVERPERMISSIVE") {
			hasNodeRoleOverpermissive = true
		}
		if idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER") {
			hasPublicLB = true
		}
		if idsContain(ids, "EKS_OIDC_PROVIDER_NOT_ASSOCIATED") {
			hasOIDCNotAssociated = true
		}
		if f.Severity == models.SeverityHigh {
			hasHighSeverity = true
		}
	}

	// ── Phase 2: annotate participating findings ───────────────────────────────

	for i := range findings {
		f := &findings[i]
		ids := ruleIDsForFinding(f)
		ns := resolveNamespaceForFinding(f)

		bestScore := 0
		bestReason := ""

		// Chain 1: Public LB + K8S_POD_RUN_AS_ROOT or K8S_POD_CAP_SYS_ADMIN
		// in the same namespace.
		if ns != "" {
			isLB := idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER")
			isPriv := idsContain(ids, "K8S_POD_RUN_AS_ROOT") || idsContain(ids, "K8S_POD_CAP_SYS_ADMIN")
			nsHasLB := nsIndexHas(nsIndex, ns, "K8S_SERVICE_PUBLIC_LOADBALANCER")
			nsHasPriv := nsIndexHas(nsIndex, ns, "K8S_POD_RUN_AS_ROOT") ||
				nsIndexHas(nsIndex, ns, "K8S_POD_CAP_SYS_ADMIN")
			if (isLB && nsHasPriv) || (isPriv && nsHasLB) {
				if 80 > bestScore {
					bestScore = 80
					bestReason = "Public service exposes privileged workload"
				}
			}
		}

		// Chain 2: K8S_DEFAULT_SERVICEACCOUNT_USED + K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT
		// in the same namespace.
		if ns != "" {
			isDefaultSA := idsContain(ids, "K8S_DEFAULT_SERVICEACCOUNT_USED")
			isAutomount := idsContain(ids, "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT")
			nsHasDefaultSA := nsIndexHas(nsIndex, ns, "K8S_DEFAULT_SERVICEACCOUNT_USED")
			nsHasAutomount := nsIndexHas(nsIndex, ns, "K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT")
			if (isDefaultSA && nsHasAutomount) || (isAutomount && nsHasDefaultSA) {
				if 60 > bestScore {
					bestScore = 60
					bestReason = "Default service account with auto-mounted token"
				}
			}
		}

		// Chain 3: K8S_CLUSTER_SINGLE_NODE + any CRITICAL severity finding.
		{
			isSingleNode := idsContain(ids, "K8S_CLUSTER_SINGLE_NODE")
			isCritical := f.Severity == models.SeverityCritical
			if (isSingleNode && hasCritical) || (isCritical && hasSingleNode) {
				if 50 > bestScore {
					bestScore = 50
					bestReason = "Single-node cluster with critical pod security violation"
				}
			}
		}

		// Chain 4 (EKS Phase 5C): EKS_NODE_ROLE_OVERPERMISSIVE + K8S_SERVICE_PUBLIC_LOADBALANCER
		// anywhere in the cluster (global scope). Score 90.
		{
			isNodeRole := idsContain(ids, "EKS_NODE_ROLE_OVERPERMISSIVE")
			isLB := idsContain(ids, "K8S_SERVICE_PUBLIC_LOADBALANCER")
			if (isNodeRole || isLB) && hasNodeRoleOverpermissive && hasPublicLB {
				if 90 > bestScore {
					bestScore = 90
					bestReason = "Public service exposed in cluster with over-permissive node IAM role."
				}
			}
		}

		// Chain 5 (EKS Phase 5C): EKS_SERVICEACCOUNT_NO_IRSA + K8S_DEFAULT_SERVICEACCOUNT_USED
		// in the same namespace. Score 85.
		if ns != "" {
			isNoIRSA := idsContain(ids, "EKS_SERVICEACCOUNT_NO_IRSA")
			isDefaultSAUsed := idsContain(ids, "K8S_DEFAULT_SERVICEACCOUNT_USED")
			nsHasNoIRSA := nsIndexHas(nsIndex, ns, "EKS_SERVICEACCOUNT_NO_IRSA")
			nsHasDefaultSAUsed := nsIndexHas(nsIndex, ns, "K8S_DEFAULT_SERVICEACCOUNT_USED")
			if (isNoIRSA && nsHasDefaultSAUsed) || (isDefaultSAUsed && nsHasNoIRSA) {
				if 85 > bestScore {
					bestScore = 85
					bestReason = "Default service account used without IRSA."
				}
			}
		}

		// Chain 6 (EKS Phase 5C): EKS_OIDC_PROVIDER_NOT_ASSOCIATED + any HIGH severity finding
		// anywhere in the cluster (global scope). Score 95.
		{
			isOIDCNotAssociated := idsContain(ids, "EKS_OIDC_PROVIDER_NOT_ASSOCIATED")
			isHigh := f.Severity == models.SeverityHigh
			if (isOIDCNotAssociated || isHigh) && hasOIDCNotAssociated && hasHighSeverity {
				if 95 > bestScore {
					bestScore = 95
					bestReason = "Cluster lacks OIDC provider and has high-risk workload findings."
				}
			}
		}

		if bestScore > 0 {
			if f.Metadata == nil {
				f.Metadata = make(map[string]any)
			}
			f.Metadata["risk_chain_score"] = bestScore
			f.Metadata["risk_chain_reason"] = bestReason
		}
	}
}
