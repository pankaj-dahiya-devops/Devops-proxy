package models

import "time"

// ---------------------------------------------------------------------------
// AWS Cost Explorer models
// ---------------------------------------------------------------------------

// AWSServiceCost holds the aggregated cost for a single AWS service.
type AWSServiceCost struct {
	Service string  `json:"service"`
	CostUSD float64 `json:"cost_usd"`
}

// AWSCostSummary holds account-level Cost Explorer data for a billing period.
type AWSCostSummary struct {
	PeriodStart      string           `json:"period_start"`
	PeriodEnd        string           `json:"period_end"`
	TotalCostUSD     float64          `json:"total_cost_usd"`
	ServiceBreakdown []AWSServiceCost `json:"service_breakdown"`
}

// ---------------------------------------------------------------------------
// AWS raw resource models (collected by provider, consumed by rule engine)
// ---------------------------------------------------------------------------

// AWSEC2Instance represents a single collected EC2 instance.
type AWSEC2Instance struct {
	InstanceID     string            `json:"instance_id"`
	Region         string            `json:"region"`
	InstanceType   string            `json:"instance_type"`
	State          string            `json:"state"`
	LaunchTime     time.Time         `json:"launch_time"`
	AvgCPUPercent  float64           `json:"avg_cpu_percent"`
	MonthlyCostUSD float64           `json:"monthly_cost_usd"`
	Tags           map[string]string `json:"tags,omitempty"`
}

// AWSEBSVolume represents a single collected EBS volume.
type AWSEBSVolume struct {
	VolumeID   string            `json:"volume_id"`
	Region     string            `json:"region"`
	VolumeType string            `json:"volume_type"`
	SizeGB     int32             `json:"size_gb"`
	State      string            `json:"state"`
	Attached   bool              `json:"attached"`
	Encrypted  bool              `json:"encrypted"`
	InstanceID string            `json:"instance_id,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// AWSNATGateway represents a single collected NAT Gateway.
type AWSNATGateway struct {
	NATGatewayID     string            `json:"nat_gateway_id"`
	Region           string            `json:"region"`
	State            string            `json:"state"`
	VPCID            string            `json:"vpc_id"`
	SubnetID         string            `json:"subnet_id"`
	BytesProcessedGB float64           `json:"bytes_processed_gb"`
	Tags             map[string]string `json:"tags,omitempty"`
}

// AWSRDSInstance represents a single collected RDS database instance.
type AWSRDSInstance struct {
	DBInstanceID     string            `json:"db_instance_id"`
	Region           string            `json:"region"`
	DBInstanceClass  string            `json:"db_instance_class"`
	Engine           string            `json:"engine"`
	MultiAZ          bool              `json:"multi_az"`
	Status           string            `json:"status"`
	StorageEncrypted bool              `json:"storage_encrypted"`
	AvgCPUPercent    float64           `json:"avg_cpu_percent"`
	MonthlyCostUSD   float64           `json:"monthly_cost_usd"`
	Tags             map[string]string `json:"tags,omitempty"`
}

// AWSLoadBalancer represents a single collected Elastic Load Balancer.
type AWSLoadBalancer struct {
	LoadBalancerARN  string            `json:"load_balancer_arn"`
	LoadBalancerName string            `json:"load_balancer_name"`
	Region           string            `json:"region"`
	Type             string            `json:"type"` // application | network | classic
	State            string            `json:"state"`
	RequestCount     int64             `json:"request_count"`
	Tags             map[string]string `json:"tags,omitempty"`
}

// AWSSavingsPlanCoverage holds Savings Plan / Reserved Instance coverage data
// for a region over the collection period.
type AWSSavingsPlanCoverage struct {
	Region          string  `json:"region"`
	CoveragePercent float64 `json:"coverage_percent"`
	OnDemandCostUSD float64 `json:"on_demand_cost_usd"`
	CoveredCostUSD  float64 `json:"covered_cost_usd"`
}

// AWSRegionData holds all raw resource data collected from a single AWS region.
// It is passed to the rule engine for evaluation.
type AWSRegionData struct {
	Region              string                   `json:"region"`
	EC2Instances        []AWSEC2Instance         `json:"ec2_instances"`
	EBSVolumes          []AWSEBSVolume           `json:"ebs_volumes"`
	NATGateways         []AWSNATGateway          `json:"nat_gateways"`
	RDSInstances        []AWSRDSInstance         `json:"rds_instances"`
	LoadBalancers       []AWSLoadBalancer        `json:"load_balancers"`
	SavingsPlanCoverage []AWSSavingsPlanCoverage `json:"savings_plan_coverage"`
	// Security holds the raw security posture data for this region and, when
	// populated by the security collector, global account-level data (IAM, root,
	// S3) is included in the Security field of the primary evaluation context.
	Security AWSSecurityData `json:"security,omitempty"`
}
