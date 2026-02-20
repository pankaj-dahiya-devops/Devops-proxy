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

// ResourceType identifies the kind of AWS resource a finding refers to.
type ResourceType string

const (
	ResourceEC2          ResourceType = "EC2_INSTANCE"
	ResourceEBS          ResourceType = "EBS_VOLUME"
	ResourceNATGateway   ResourceType = "NAT_GATEWAY"
	ResourceRDS          ResourceType = "RDS_INSTANCE"
	ResourceLoadBalancer ResourceType = "LOAD_BALANCER"
	ResourceSavingsPlan  ResourceType = "SAVINGS_PLAN"
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
	ReportID    string       `json:"report_id"`
	GeneratedAt time.Time    `json:"generated_at"`
	AuditType   string       `json:"audit_type"`
	Profile     string       `json:"profile"`
	AccountID   string       `json:"account_id"`
	Regions     []string     `json:"regions"`
	Summary     AuditSummary `json:"summary"`
	Findings    []Finding    `json:"findings"`
	CostSummary *CostSummary `json:"cost_summary,omitempty"`
}

// ---------------------------------------------------------------------------
// Cost Explorer models
// ---------------------------------------------------------------------------

// ServiceCost holds the aggregated cost for a single AWS service.
type ServiceCost struct {
	Service string  `json:"service"`
	CostUSD float64 `json:"cost_usd"`
}

// CostSummary holds account-level Cost Explorer data for a billing period.
type CostSummary struct {
	PeriodStart      string        `json:"period_start"`
	PeriodEnd        string        `json:"period_end"`
	TotalCostUSD     float64       `json:"total_cost_usd"`
	ServiceBreakdown []ServiceCost `json:"service_breakdown"`
}

// ---------------------------------------------------------------------------
// Raw resource models (collected by provider, consumed by rule engine)
// ---------------------------------------------------------------------------

// EC2Instance represents a single collected EC2 instance.
type EC2Instance struct {
	InstanceID     string            `json:"instance_id"`
	Region         string            `json:"region"`
	InstanceType   string            `json:"instance_type"`
	State          string            `json:"state"`
	LaunchTime     time.Time         `json:"launch_time"`
	AvgCPUPercent  float64           `json:"avg_cpu_percent"`
	MonthlyCostUSD float64           `json:"monthly_cost_usd"`
	Tags           map[string]string `json:"tags,omitempty"`
}

// EBSVolume represents a single collected EBS volume.
type EBSVolume struct {
	VolumeID   string            `json:"volume_id"`
	Region     string            `json:"region"`
	VolumeType string            `json:"volume_type"`
	SizeGB     int32             `json:"size_gb"`
	State      string            `json:"state"`
	Attached   bool              `json:"attached"`
	InstanceID string            `json:"instance_id,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// NATGateway represents a single collected NAT Gateway.
type NATGateway struct {
	NATGatewayID     string            `json:"nat_gateway_id"`
	Region           string            `json:"region"`
	State            string            `json:"state"`
	VPCID            string            `json:"vpc_id"`
	SubnetID         string            `json:"subnet_id"`
	BytesProcessedGB float64           `json:"bytes_processed_gb"`
	Tags             map[string]string `json:"tags,omitempty"`
}

// RDSInstance represents a single collected RDS database instance.
type RDSInstance struct {
	DBInstanceID    string            `json:"db_instance_id"`
	Region          string            `json:"region"`
	DBInstanceClass string            `json:"db_instance_class"`
	Engine          string            `json:"engine"`
	MultiAZ         bool              `json:"multi_az"`
	Status          string            `json:"status"`
	Tags            map[string]string `json:"tags,omitempty"`
}

// LoadBalancer represents a single collected Elastic Load Balancer.
type LoadBalancer struct {
	LoadBalancerARN  string            `json:"load_balancer_arn"`
	LoadBalancerName string            `json:"load_balancer_name"`
	Region           string            `json:"region"`
	Type             string            `json:"type"` // application | network | classic
	State            string            `json:"state"`
	RequestCount     int64             `json:"request_count"`
	Tags             map[string]string `json:"tags,omitempty"`
}

// SavingsPlanCoverage holds Savings Plan / Reserved Instance coverage data
// for a region over the collection period.
type SavingsPlanCoverage struct {
	Region          string  `json:"region"`
	CoveragePercent float64 `json:"coverage_percent"`
	OnDemandCostUSD float64 `json:"on_demand_cost_usd"`
	CoveredCostUSD  float64 `json:"covered_cost_usd"`
}

// RegionData holds all raw resource data collected from a single AWS region.
// It is passed to the rule engine for evaluation.
type RegionData struct {
	Region              string                `json:"region"`
	EC2Instances        []EC2Instance         `json:"ec2_instances"`
	EBSVolumes          []EBSVolume           `json:"ebs_volumes"`
	NATGateways         []NATGateway          `json:"nat_gateways"`
	RDSInstances        []RDSInstance         `json:"rds_instances"`
	LoadBalancers       []LoadBalancer        `json:"load_balancers"`
	SavingsPlanCoverage []SavingsPlanCoverage `json:"savings_plan_coverage"`
}
