package models

import "time"

// Severity represents the impact level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// ResourceType identifies the kind of cloud resource a finding refers to.
type ResourceType string

const (
	// AWS resource types
	ResourceAWSEC2           ResourceType = "EC2_INSTANCE"
	ResourceAWSEBS           ResourceType = "EBS_VOLUME"
	ResourceAWSNATGateway    ResourceType = "NAT_GATEWAY"
	ResourceAWSRDS           ResourceType = "RDS_INSTANCE"
	ResourceAWSLoadBalancer  ResourceType = "LOAD_BALANCER"
	ResourceAWSSavingsPlan   ResourceType = "SAVINGS_PLAN"
	ResourceAWSS3Bucket      ResourceType = "S3_BUCKET"
	ResourceAWSSecurityGroup ResourceType = "SECURITY_GROUP"
	ResourceAWSIAMUser       ResourceType = "IAM_USER"
	ResourceAWSRootAccount   ResourceType = "ROOT_ACCOUNT"

	// Kubernetes resource types
	ResourceK8sNode           ResourceType = "K8S_NODE"
	ResourceK8sNamespace      ResourceType = "K8S_NAMESPACE"
	ResourceK8sCluster        ResourceType = "K8S_CLUSTER"
	ResourceK8sPod            ResourceType = "K8S_POD"
	ResourceK8sService        ResourceType = "K8S_SERVICE"
	ResourceK8sServiceAccount ResourceType = "K8S_SERVICEACCOUNT"
)

// Finding is a single detected waste or inefficiency issue.
// It is the atomic output unit of the rule engine.
type Finding struct {
	ID                      string         `json:"id"`
	RuleID                  string         `json:"rule_id"`
	ResourceID              string         `json:"resource_id"`
	ResourceType            ResourceType   `json:"resource_type"`
	Region                  string         `json:"region"`
	AccountID               string         `json:"account_id"`
	Profile                 string         `json:"profile"`
	Domain                  string         `json:"domain"`
	Severity                Severity       `json:"severity"`
	EstimatedMonthlySavings float64        `json:"estimated_monthly_savings_usd"`
	Explanation             string         `json:"explanation"`
	Recommendation          string         `json:"recommendation"`
	DetectedAt              time.Time      `json:"detected_at"`
	Metadata                map[string]any `json:"metadata,omitempty"`
}

// AuditSummary aggregates counts and totals across all findings.
type AuditSummary struct {
	TotalFindings                int     `json:"total_findings"`
	CriticalFindings             int     `json:"critical_findings"`
	HighFindings                 int     `json:"high_findings"`
	MediumFindings               int     `json:"medium_findings"`
	LowFindings                  int     `json:"low_findings"`
	TotalEstimatedMonthlySavings float64 `json:"total_estimated_monthly_savings_usd"`
}

// AuditReport is the top-level, SaaS-compatible output of any audit run.
type AuditReport struct {
	ReportID    string          `json:"report_id"`
	GeneratedAt time.Time       `json:"generated_at"`
	AuditType   string          `json:"audit_type"`
	Profile     string          `json:"profile"`
	AccountID   string          `json:"account_id"`
	Regions     []string        `json:"regions"`
	Summary     AuditSummary    `json:"summary"`
	Findings    []Finding       `json:"findings"`
	CostSummary *AWSCostSummary `json:"cost_summary,omitempty"`
	// Metadata carries optional, audit-type-specific key/value pairs.
	// For Kubernetes audits this includes "cluster_provider".
	Metadata map[string]any `json:"metadata,omitempty"`
}
