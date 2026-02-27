# DevOps Proxy (dp)

An extensible DevOps execution engine with deterministic rule-based analysis and optional AI summarisation.

Currently implements: **AWS cost audit**, **AWS security audit**, **AWS data protection audit**, **Kubernetes governance audit**, and a **unified `--all` mode** that runs all three AWS domains in one shot — multi-profile, multi-region, CloudWatch-backed.

---

## Overview

`dp` collects raw AWS resource data, runs a deterministic rule engine to detect waste and inefficiencies, and returns structured findings with severity rankings and estimated monthly savings.

- Multi-profile and multi-region out of the box
- Rule engine works fully offline — no LLM required
- Real CloudWatch CPU data for EC2 and RDS analysis
- Cost Explorer per-instance cost data for EC2 and RDS savings estimation
- S3 public access, IAM MFA, root access key, and open SSH/RDP security checks
- Data protection: EBS encryption, RDS storage encryption, S3 default encryption checks
- Per-resource finding merge: multiple rules on the same resource are collapsed into a single finding with summed savings
- JSON output is SaaS-compatible from day one

---

## Policy Configuration (`dp.yaml`)

`dp` supports an optional policy file that controls which findings are surfaced
and at what severity — without changing any rule logic.

The policy layer sits between rule evaluation and report assembly:

```
Collect → Evaluate → Merge → ApplyPolicy → Sort → Summary → AuditReport
```

### Example `dp.yaml`

```yaml
version: 1

domains:
  cost:
    enabled: true        # set to false to suppress ALL cost findings
    min_severity: HIGH   # drop findings whose final severity is below HIGH
  security:
    enabled: true
    min_severity: MEDIUM

rules:
  EC2_LOW_CPU:
    enabled: false       # silence this rule entirely
    params:
      cpu_threshold: 15.0  # raise threshold from default 10% to 15%
  SG_OPEN_SSH:
    severity: CRITICAL   # escalate from HIGH to CRITICAL
  NAT_LOW_TRAFFIC:
    params:
      traffic_gb_threshold: 2.0  # raise threshold from default 1 GB to 2 GB

enforcement:
  cost:
    fail_on_severity: HIGH       # exit 1 if any cost finding is HIGH or above
  security:
    fail_on_severity: CRITICAL   # exit 1 only for CRITICAL security findings
  dataprotection:
    fail_on_severity: HIGH
```

### Behaviour

| Scenario | Result |
|----------|--------|
| No policy file | Default behaviour — all findings returned at rule-defined severity |
| `domains.cost.enabled: false` | All cost findings dropped |
| `domains.cost.min_severity: HIGH` | Findings with final severity MEDIUM, LOW, or INFO are dropped |
| `rules.EC2_LOW_CPU.enabled: false` | All `EC2_LOW_CPU` findings dropped |
| `rules.SG_OPEN_SSH.severity: CRITICAL` | Finding severity replaced with `CRITICAL` |
| `rules.EC2_LOW_CPU.params.cpu_threshold: 15.0` | CPU threshold raised to 15% (overrides default 10%) |
| `enforcement.cost.fail_on_severity: HIGH` | Exit code 1 if any cost finding is HIGH or CRITICAL |
| Rule not listed in policy | Pass through unchanged |

**Severity override + min_severity interact correctly:** the severity override is applied first,
then the min_severity filter evaluates the post-override severity. A MEDIUM finding overridden
to CRITICAL will survive a `min_severity: HIGH` filter.

**Enforcement fires after all output:** JSON/table/summary is always printed to stdout before
the exit-code check. stderr receives the enforcement error message.

**JSON mode produces pure JSON:** When `--output json` is set, stdout contains **only the JSON
payload** — no banner lines, no summary text, no table headers, no context lines. JSON mode
takes priority even when `--summary` is also passed. The stderr message
`"audit completed with CRITICAL or HIGH findings"` is also suppressed in JSON mode to prevent
contaminating piped streams. Exit code 1 is still raised unconditionally when CRITICAL or HIGH
findings exist, regardless of output format.

**Severity ordering:** `CRITICAL > HIGH > MEDIUM > LOW > INFO`

**Rules supporting threshold params:**

| Rule ID | Param key | Default |
|---------|-----------|---------|
| `EC2_LOW_CPU` | `cpu_threshold` | `10.0` |
| `RDS_LOW_CPU` | `cpu_threshold` | `10.0` |
| `NAT_LOW_TRAFFIC` | `traffic_gb_threshold` | `1.0` |

### CI usage

```bash
# Fail CI if any HIGH or above cost finding is detected
./dp aws audit cost --policy ./dp.yaml
echo $?   # 1 if HIGH+ findings present, 0 otherwise

# Capture JSON report and still enforce
./dp aws audit security --policy ./dp.yaml --output=json > report.json
```

### Using `--policy`

Pass the policy file explicitly, or place `dp.yaml` in the working directory for automatic detection:

```bash
# Explicit path
./dp aws audit cost --policy ./dp.yaml

# Auto-detected (dp.yaml exists in current directory)
./dp aws audit cost

# Works the same for security and data protection
./dp aws audit security --policy ./dp.yaml
./dp aws audit dataprotection --policy ./dp.yaml
```

### Integration status

| Engine | `--policy` flag | ApplyPolicy called | Domain |
|--------|-----------------|-------------------|--------|
| `dp aws audit cost` | ✅ | ✅ | `"cost"` |
| `dp aws audit security` | ✅ | ✅ | `"security"` |
| `dp aws audit dataprotection` | ✅ | ✅ | `"dataprotection"` |
| `dp aws audit --all` | ✅ | ✅ per domain | `"cost"`, `"security"`, `"dataprotection"` |

The policy layer is entirely optional and non-invasive: if no policy file is
provided, behavior is identical to previous releases.

---

## Installation (Binary)

Pre-built binaries for Linux, macOS, and Windows are available on the
[GitHub Releases page](https://github.com/pankaj-dahiya-devops/Devops-proxy/releases).

Download the archive for your platform, extract it, and place the `dp` binary on your `PATH`:

```bash
# Example: Linux amd64
curl -L https://github.com/pankaj-dahiya-devops/Devops-proxy/releases/latest/download/dp_<version>_Linux_amd64.tar.gz | tar xz
chmod +x dp
sudo mv dp /usr/local/bin/
```

```bash
# Example: macOS arm64 (Apple Silicon)
curl -L https://github.com/pankaj-dahiya-devops/Devops-proxy/releases/latest/download/dp_<version>_macOS_arm64.tar.gz | tar xz
chmod +x dp
sudo mv dp /usr/local/bin/
```

Windows users can download the `.zip` archive from the Releases page and extract `dp.exe`.

---

## Installation (From Source)

**Requirements:** Go 1.22+, AWS credentials configured (`~/.aws/credentials` or environment variables)

```bash
git clone https://github.com/pankaj-dahiya-devops/Devops-proxy.git
cd Devops-proxy
go build -o dp ./cmd/dp
```

---

## Usage

### AWS cost audit

```bash
# Audit default profile, table output
./dp aws audit cost

# Named profile, JSON output
./dp aws audit cost --profile staging --output=json

# All configured profiles
./dp aws audit cost --all-profiles

# Explicit regions, 14-day lookback
./dp aws audit cost --profile prod --region us-east-1 --region eu-west-1 --days 14

# Compact summary to stdout, also save full JSON report to file
./dp aws audit cost --profile prod --summary --file report.json

# Table output to stdout and full JSON saved to file
./dp aws audit cost --file /tmp/audit.json
```

#### Flags (`dp aws audit cost`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | Named AWS profile (empty = default/env credentials) |
| `--all-profiles` | bool | `false` | Audit every profile in `~/.aws/config` |
| `--region` | []string | `nil` | Explicit regions; omit to auto-discover active regions |
| `--days` | int | `30` | Lookback window for cost and CloudWatch metric queries |
| `--output` | string | `table` | Output format: `table` or `json` |
| `--summary` | bool | `false` | Print compact summary: totals, severity breakdown, top-5 findings |
| `--file` | string | `""` | Write full JSON report to file (does not suppress stdout output) |
| `--policy` | string | `""` | Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists) |

### AWS security audit

```bash
# Audit default profile, table output
./dp aws audit security

# Named profile, JSON output
./dp aws audit security --profile staging --output=json

# All configured profiles
./dp aws audit security --all-profiles

# Specific regions with compact summary
./dp aws audit security --region us-east-1 --region eu-west-1 --summary

# Save full JSON report to file
./dp aws audit security --file security-report.json
```

#### Flags (`dp aws audit security`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | Named AWS profile (empty = default/env credentials) |
| `--all-profiles` | bool | `false` | Audit every profile in `~/.aws/config` |
| `--region` | []string | `nil` | Explicit regions; omit to auto-discover active regions |
| `--output` | string | `table` | Output format: `table` or `json` |
| `--summary` | bool | `false` | Print compact summary: totals, severity breakdown, top-5 findings |
| `--file` | string | `""` | Write full JSON report to file (does not suppress stdout output) |
| `--policy` | string | `""` | Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists) |

### AWS data protection audit

```bash
# Audit default profile, table output
./dp aws audit dataprotection

# Named profile, JSON output
./dp aws audit dataprotection --profile staging --output=json

# All configured profiles
./dp aws audit dataprotection --all-profiles

# Specific regions with compact summary
./dp aws audit dataprotection --region us-east-1 --region eu-west-1 --summary

# Save full JSON report to file
./dp aws audit dataprotection --file dp-report.json
```

#### Flags (`dp aws audit dataprotection`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | Named AWS profile (empty = default/env credentials) |
| `--all-profiles` | bool | `false` | Audit every profile in `~/.aws/config` |
| `--region` | []string | `nil` | Explicit regions; omit to auto-discover active regions |
| `--output` | string | `table` | Output format: `table` or `json` |
| `--summary` | bool | `false` | Print compact summary: totals, severity breakdown, top-5 findings |
| `--file` | string | `""` | Write full JSON report to file (does not suppress stdout output) |
| `--policy` | string | `""` | Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists) |

### Unified AWS audit (`dp aws audit --all`)

Runs all three AWS audit domains (cost, security, dataprotection) in one command
and returns a single merged report. Policy is applied per-domain before merge;
findings from different domains for the same resource are deduplicated (highest
severity wins, savings summed).

> **Provider boundary:** `dp aws audit --all` is AWS-scoped. Kubernetes belongs
> to its own command: `dp kubernetes audit`.

```bash
# Run all AWS domains, table output
./dp aws audit --all

# Named profile, JSON output, save to file
./dp aws audit --all --profile staging --output=json --file all-report.json

# All profiles, compact summary
./dp aws audit --all --all-profiles --summary

# Specific regions
./dp aws audit --all --region us-east-1 --region eu-west-1

# With policy enforcement (exit 1 if any domain triggers fail_on_severity)
./dp aws audit --all --policy ./dp.yaml
```

#### Output (`--all`, default table)

```
Profile: default       Account: 123456789012  Regions: 3  Findings: 6  Est. Savings: $88.00/mo

RESOURCE ID                                REGION           SEVERITY    TYPE                  SAVINGS/MO
-------------------------------------------------------------------------------------------------------
123456789012                               global           CRITICAL    ROOT_ACCOUNT           $0.00
mydb-prod                                  us-east-1        CRITICAL    RDS_INSTANCE           $0.00
vol-0abc123                                us-east-1        HIGH        EBS_VOLUME             $8.00
my-public-bucket                           global           HIGH        S3_BUCKET              $0.00
```

#### Flags (`dp aws audit --all`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Run all AWS audit domains: cost, security, dataprotection |
| `--profile` | string | `""` | Named AWS profile (empty = default/env credentials) |
| `--all-profiles` | bool | `false` | Audit every profile in `~/.aws/config` |
| `--region` | []string | `nil` | Explicit regions; omit to auto-discover active regions |
| `--days` | int | `30` | Lookback window for cost queries |
| `--output` | string | `table` | Output format: `table` or `json` |
| `--summary` | bool | `false` | Print compact summary: totals, severity breakdown, top-5 findings |
| `--file` | string | `""` | Write full JSON report to file (does not suppress stdout output) |
| `--policy` | string | `""` | Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists) |

#### Merging behaviour

| Scenario | Result |
|----------|--------|
| Same resource in cost and dataprotection | Single finding: highest severity, summed savings |
| Different resources across domains | Kept as separate findings |
| Policy per-domain | Applied inside each engine before global merge |
| Policy enforcement | Exit 1 if any domain triggers `fail_on_severity`; all output is printed first |
| `audit_type` in JSON | `"all"` |

### Kubernetes audit

```bash
# Audit current kubeconfig context, table output
./dp kubernetes audit

# Audit a specific context, JSON output
./dp kubernetes audit --context prod-eks --output=json

# Compact summary
./dp kubernetes audit --summary

# Save full JSON report to file
./dp kubernetes audit --file k8s-report.json

# With policy enforcement
./dp kubernetes audit --policy ./dp.yaml

# Exclude findings from system namespaces (kube-system, kube-public, kube-node-lease)
./dp kubernetes audit --exclude-system
```

#### Flags (`dp kubernetes audit`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--context` | string | `""` | Kubeconfig context to use (empty = current context) |
| `--output` | string | `table` | Output format: `table` or `json` |
| `--summary` | bool | `false` | Print compact summary: totals, severity breakdown, top-5 findings |
| `--file` | string | `""` | Write full JSON report to file (does not suppress stdout output) |
| `--policy` | string | `""` | Path to dp.yaml policy file (auto-detected if omitted and ./dp.yaml exists) |
| `--exclude-system` | bool | `false` | Exclude findings from system namespaces (kube-system, kube-public, kube-node-lease) |
| `--min-risk-score` | int | `0` | Only include findings with a `risk_chain_score` ≥ this value (0 = include all) |

#### Namespace Classification (Phase 3C)

Every finding in a Kubernetes audit report carries a `namespace_type` metadata key:

| Value | Meaning |
|-------|---------|
| `"system"` | Finding belongs to a system namespace: `kube-system`, `kube-public`, or `kube-node-lease` |
| `"workload"` | Finding belongs to a user namespace (e.g. `production`, `staging`, `default`) |
| `"cluster"` | Finding is cluster-scoped and has no namespace (nodes, cluster-level, EKS control-plane rules) |

This classification is always present in the JSON output regardless of `--exclude-system`:

```json
{
  "rule_id": "K8S_PRIVILEGED_CONTAINER",
  "resource_id": "my-pod",
  "resource_type": "K8S_POD",
  "metadata": {
    "namespace": "production",
    "namespace_type": "workload",
    "container_name": "app"
  }
}
```

Use `--exclude-system` to suppress findings from system namespaces in CI pipelines where system-level noise is expected:

```bash
# CI: fail only on workload findings, ignore system namespace issues
./dp kubernetes audit --exclude-system --policy ./dp.yaml
```

#### Risk Correlation (Phase 4A)

After findings are generated, the engine runs a compound risk correlation pass. Findings that participate in a multi-signal risk chain are annotated with two extra metadata keys:

| Key | Type | Description |
|-----|------|-------------|
| `risk_chain_score` | int | Compound risk score (higher = more dangerous) |
| `risk_chain_reason` | string | Human-readable explanation for the chain |

Three chains are detected:

| Score | Chain | Condition |
|-------|-------|-----------|
| **80** | Public LB + privileged workload | A `K8S_SERVICE_PUBLIC_LOADBALANCER` service and a pod with `K8S_POD_RUN_AS_ROOT` or `K8S_POD_CAP_SYS_ADMIN` co-exist in the **same namespace** |
| **60** | Default SA + automount | A pod uses the default ServiceAccount (`K8S_DEFAULT_SERVICEACCOUNT_USED`) and the SA has token automount enabled (`K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT`) in the **same namespace** |
| **50** | Single-node + critical violation | The cluster has one node (`K8S_CLUSTER_SINGLE_NODE`) **and** a CRITICAL severity finding exists |

When a finding participates in multiple chains, the highest score is kept. Severity and sort order are unchanged.

The highest score across all correlated findings is also surfaced in `report.summary.risk_score` for easy machine consumption:

```json
{
  "summary": {
    "total_findings": 4,
    "critical_findings": 1,
    "high_findings": 2,
    "medium_findings": 1,
    "low_findings": 0,
    "total_estimated_monthly_savings_usd": 0,
    "risk_score": 80
  }
}
```

`risk_score` is `0` when no risk chain fires. It reflects the pre-policy merged finding set — computed before `--min-risk-score` filtering — so the summary always shows the true cluster risk level regardless of what the caller chose to display.

#### Filtering by Risk Score (Phase 4C)

Use `--min-risk-score` to narrow the report to only findings that participate in a risk chain at or above the given threshold:

```bash
# Show only findings with a risk chain score >= 60 (chains 1 and 2)
./dp kubernetes audit --min-risk-score 60

# Show only the highest-priority chain (score >= 80, chain 1 only)
./dp kubernetes audit --min-risk-score 80 --output json

# Combine with --exclude-system to focus on workload risk chains only
./dp kubernetes audit --min-risk-score 60 --exclude-system
```

Findings with no chain score (`risk_chain_score` == 0) are always excluded when `--min-risk-score > 0`. `Summary.RiskScore` is computed on the pre-filter set and is unaffected by this flag.

Example JSON output for a chain-1 finding:

```json
{
  "rule_id": "K8S_SERVICE_PUBLIC_LOADBALANCER",
  "resource_id": "web-svc",
  "resource_type": "K8S_SERVICE",
  "severity": "HIGH",
  "metadata": {
    "namespace": "production",
    "namespace_type": "workload",
    "risk_chain_score": 80,
    "risk_chain_reason": "Public service exposes privileged workload"
  }
}
```

---

### Kubernetes inspect

```bash
# Inspect current kubeconfig context
./dp kubernetes inspect

# Inspect a specific context
./dp kubernetes inspect --context my-cluster
```

#### Flags (`dp kubernetes inspect`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--context` | string | `""` | Kubeconfig context to use (empty = current context) |

### Version

```bash
dp version
```

Prints the binary version, git commit, and build date:

```
dp version v0.4.0
commit: a1b2c3d
built: 2026-02-22
```

When built locally with `go build`, the defaults `dev / none / unknown` are used.

---

### Doctor

```bash
dp doctor [--profile=<name>] [--format=table|json]
```

Runs environment diagnostics and reports the status of AWS credentials, Kubernetes connectivity, and the optional policy file. Useful for first-time setup verification and CI preflight checks.

#### Flags (`dp doctor`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | AWS profile to use (empty = default credential chain) |
| `--format` | string | `"table"` | Output format: `table` or `json` |

#### Table output (default)

```
Environment Diagnostics

AWS (profile: prod):
  Credentials: OK
  STS Identity: OK (Account: 123456789012)
  Regions API: OK

Kubernetes:
  Kubeconfig: OK
  Current Context: OK (prod-eks)
  API Reachable: OK

Policy:
  dp.yaml present: YES
  Policy valid: OK
```

When `--profile` is omitted the header shows `AWS:` (no profile qualifier).

#### JSON output (`--format=json`)

```json
{
  "aws": {
    "profile": "prod",
    "credentials_ok": true,
    "account_id": "123456789012",
    "regions_ok": true
  },
  "kubernetes": {
    "kubeconfig_ok": true,
    "context": "prod-eks",
    "api_reachable": true
  },
  "policy": {
    "present": true,
    "valid": true
  },
  "overall_healthy": true
}
```

`aws.profile` is omitted from JSON when `--profile` is not set. JSON is emitted even when `overall_healthy` is `false`, so callers can parse and act on the structured result.

Exit codes:
- **0** — all checks passed, or only the policy file is missing (it is optional)
- **1** — AWS or Kubernetes checks failed, or a policy file is present but invalid

---

## Example Output

### `dp kubernetes inspect`

```
Context:     prod-eks
API Server:  https://ABCD1234.gr7.us-east-1.eks.amazonaws.com
Nodes:       6
Namespaces:  12
```

### AWS security audit — Table

```
Profile: default       Account: 123456789012  Regions: 3  Findings: 3

RESOURCE ID                                REGION           SEVERITY    TYPE
----------------------------------------------------------------------------------------
123456789012                               global           CRITICAL    ROOT_ACCOUNT
my-public-bucket                           global           HIGH        S3_BUCKET
sg-0abc1234def567890                       us-east-1        HIGH        SECURITY_GROUP
bob                                        global           MEDIUM      IAM_USER
```

### AWS data protection audit — Table

```
Profile: default       Account: 123456789012  Regions: 3  Findings: 3

RESOURCE ID                                REGION           SEVERITY    TYPE
----------------------------------------------------------------------------------------
mydb-prod                                  us-east-1        CRITICAL    RDS_INSTANCE
vol-0abc1234def567890                      eu-west-1        HIGH        EBS_VOLUME
my-unencrypted-bucket                      global           HIGH        S3_BUCKET
```

### AWS cost audit — Table

```
Profile: default       Account: 123456789012  Regions: 3  Findings: 4  Est. Savings: $108.00/mo

RESOURCE ID                                REGION           SEVERITY    SAVINGS/MO
----------------------------------------------------------------------------------
mydb-prod                                  us-east-1        HIGH        $60.00
i-0a1b2c3d4e5f67890                        us-east-1        MEDIUM      $30.00
vol-0abc1234def567890                      us-east-1        MEDIUM      $16.00
vol-0def5678abc123456                      eu-west-1        LOW         $2.00
```

### AWS cost audit — JSON

```json
{
  "report_id": "audit-1740000000000000000",
  "audit_type": "cost",
  "profile": "default",
  "account_id": "123456789012",
  "regions": ["us-east-1", "eu-west-1"],
  "summary": {
    "total_findings": 4,
    "high_findings": 1,
    "medium_findings": 2,
    "low_findings": 1,
    "total_estimated_monthly_savings_usd": 108.00
  },
  "findings": [
    {
      "id": "RDS_LOW_CPU-mydb-prod",
      "rule_id": "RDS_LOW_CPU",
      "resource_id": "mydb-prod",
      "resource_type": "RDS_INSTANCE",
      "region": "us-east-1",
      "severity": "HIGH",
      "estimated_monthly_savings_usd": 60.00,
      "explanation": "RDS instance class may be overprovisioned.",
      "recommendation": "Review instance sizing and consider downsizing to a smaller DB instance class.",
      "metadata": {
        "avg_cpu_percent": 2.1,
        "monthly_cost_usd": 200.00
      }
    },
    {
      "id": "EC2_LOW_CPU-i-0a1b2c3d4e5f67890",
      "rule_id": "EC2_LOW_CPU",
      "resource_id": "i-0a1b2c3d4e5f67890",
      "resource_type": "EC2_INSTANCE",
      "region": "us-east-1",
      "severity": "MEDIUM",
      "estimated_monthly_savings_usd": 30.00,
      "explanation": "Instance type may be overprovisioned.",
      "recommendation": "Review instance sizing and consider downsizing or Savings Plan.",
      "metadata": {
        "avg_cpu_percent": 2.4,
        "instance_type": "m5.xlarge",
        "monthly_cost_usd": 100.00,
        "rules": ["EC2_LOW_CPU"]
      }
    }
  ]
}
```

---

## Architecture

```
cmd/dp/
  main.go          Entry point
  commands.go      Cobra commands, flag parsing, output rendering

internal/engine/
  engine.go           Engine interface, AuditOptions, AuditType
  aws_cost.go         AWSCostEngine: orchestrates cost collection → rules → merge → sort → report
  aws_security.go     AWSSecurityEngine: orchestrates security collection → rules → report
  aws_dataprotection.go AWSDataProtectionEngine: EBS/RDS (cost collector) + S3 (security collector)

internal/providers/aws/
  common/          AWSClientProvider: profile loading, region discovery
  cost/            CostCollector: EC2, EBS, NAT, RDS, ELB, Savings Plan, Cost Explorer
  security/        SecurityCollector: S3, EC2 security groups, IAM users, root account

internal/providers/kubernetes/
  models.go        ClusterInfo, NodeInfo, NamespaceInfo, ClusterData
  client.go        KubeClientProvider interface, DefaultKubeClientProvider
  loader.go        LoadClientset: kubeconfig → clientset + ClusterInfo
  collector.go     CollectClusterData: nodes + namespaces (accepts kubernetes.Interface)

internal/rules/
  rule.go                               Rule interface, RuleContext, RuleRegistry interface
  registry.go                           DefaultRuleRegistry
  aws_ec2_low_cpu.go                    EC2_LOW_CPU: running instances with avg CPU < 10%
  aws_ebs_unattached.go                 EBS_UNATTACHED: volumes in "available" state
  aws_ebs_gp2_legacy.go                EBS_GP2_LEGACY: gp2 volumes that should migrate to gp3
  aws_nat_low_traffic.go                NAT_LOW_TRAFFIC: gateways with < 1 GB traffic
  aws_savings_plan_underutilized.go     SAVINGS_PLAN_UNDERUTILIZED: SP coverage < 60%
  aws_rds_low_cpu.go                    RDS_LOW_CPU: available instances with avg CPU < 10%
  aws_root_access_key.go                ROOT_ACCESS_KEY: root account has active access keys
  aws_s3_public_bucket.go               S3_PUBLIC_BUCKET: bucket lacks full public access block
  aws_sg_open_ssh.go                    SG_OPEN_SSH: security group exposes SSH/RDP to 0.0.0.0/0
  aws_iam_user_no_mfa.go               IAM_USER_NO_MFA: console IAM user has no MFA device
  aws_ebs_unencrypted.go                EBS_UNENCRYPTED: EBS volume not encrypted at rest
  aws_rds_unencrypted.go                RDS_UNENCRYPTED: RDS instance storage not encrypted
  aws_s3_default_encryption_missing.go  S3_DEFAULT_ENCRYPTION_MISSING: bucket has no default SSE
  k8s_rules.go                          K8S rules: single-node, overallocated, namespace limits,
                                         privileged container, public LoadBalancer, pod no requests

internal/rulepacks/aws_cost/
  pack.go          New() []rules.Rule — all 6 cost rules

internal/rulepacks/aws_security/
  pack.go          New() []rules.Rule — all 4 security rules

internal/rulepacks/aws_dataprotection/
  pack.go          New() []rules.Rule — 3 data-protection rules (RDS, EBS, S3)

internal/rulepacks/kubernetes/
  pack.go          New() []rules.Rule — 6 Kubernetes governance rules

internal/models/
  findings.go      Cloud-agnostic core: Severity, ResourceType, Finding, AuditSummary, AuditReport
  aws.go           AWS raw infrastructure types: AWSEC2Instance, AWSEBSVolume, AWSNATGateway,
                   AWSRDSInstance, AWSLoadBalancer, AWSSavingsPlanCoverage, AWSRegionData,
                   AWSServiceCost, AWSCostSummary
  aws_security.go  AWS security types: AWSSecurityData, AWSS3Bucket, AWSSecurityGroupRule,
                   AWSIAMUser, AWSRootAccountInfo
  kubernetes.go    KubernetesClusterData, KubernetesNodeData, KubernetesNamespaceData
```

### Engine pipeline

```
LoadProfile(s)
  → CollectAll (EC2 + CloudWatch, EBS, NAT, RDS, ELB, Savings Plan, Cost Explorer)
  → EvaluateAll (rule engine, per region)
  → mergeFindings (group by ResourceID+Region: highest severity, summed savings)
  → ApplyPolicy (drop / override severity per domain and rule — no-op if no policy file)
  → sortFindings (CRITICAL → HIGH → MEDIUM → LOW → INFO, ties by savings desc)
  → AuditReport
```

### Cost rules

| Rule ID | Trigger | Severity | Savings estimate |
|---------|---------|----------|-----------------|
| EC2_LOW_CPU | avg CPU > 0% and < 10% over lookback period | MEDIUM | 30% of CE monthly cost |
| EBS_UNATTACHED | volume state == "available", not attached | MEDIUM | SizeGB × $0.08/mo |
| EBS_GP2_LEGACY | volume type == "gp2" | LOW | SizeGB × $0.02/mo |
| NAT_LOW_TRAFFIC | state == "available" and BytesOutToDestination < 1 GB | HIGH | $32/mo (fixed hourly cost) |
| SAVINGS_PLAN_UNDERUTILIZED | SP coverage < 60% and on-demand cost > $100 | HIGH / MEDIUM | 10% of on-demand cost |
| RDS_LOW_CPU | status == "available", avg CPU > 0% and < 10% | HIGH (< 5%) / MEDIUM | 30% of CE monthly cost |
| ALB_IDLE | Application LB active with RequestCount == 0 over lookback window | HIGH | ~$18/mo |
| EC2_NO_SAVINGS_PLAN | EC2 on-demand instances with zero Savings Plan coverage in region | HIGH | 20% of on-demand cost |

### Security rules

| Rule ID | Trigger | Severity |
|---------|---------|----------|
| ROOT_ACCESS_KEY | Root account has ≥ 1 active access key (IAM GetAccountSummary) | CRITICAL |
| ROOT_ACCOUNT_MFA_DISABLED | Root account MFA not enabled (`AccountMFAEnabled == 0`) | CRITICAL |
| CLOUDTRAIL_NOT_MULTI_REGION | No CloudTrail trail configured with `IsMultiRegionTrail == true` | HIGH |
| S3_PUBLIC_BUCKET | `GetBucketPolicyStatus` `IsPublic == true`; no-policy buckets → NOT flagged | HIGH |
| SG_OPEN_SSH | Security group allows port 22 or 3389 from 0.0.0.0/0 or ::/0 | HIGH |
| GUARDDUTY_DISABLED | GuardDuty detector not in ENABLED state in one or more regions | HIGH |
| AWS_CONFIG_DISABLED | AWS Config recorder not actively recording in one or more regions | HIGH |
| IAM_USER_NO_MFA | Console IAM user (`HasLoginProfile == true`) with no MFA device | MEDIUM |

### Data protection rules

| Rule ID | Trigger | Severity |
|---------|---------|----------|
| RDS_UNENCRYPTED | RDS instance `StorageEncrypted == false` | CRITICAL |
| EBS_UNENCRYPTED | EBS volume `Encrypted == false` | HIGH |
| S3_DEFAULT_ENCRYPTION_MISSING | S3 bucket has no server-side encryption configuration | HIGH |

### Test coverage

Unit tests across rule engine, policy layer, data-protection rules, security rules, k8s provider, engine core, and CLI:
- `AWSEBSUnattachedRule` — 9 subtests (trigger logic, savings calculation, field validation)
- `AWSEBSGP2LegacyRule` — 10 subtests (all non-gp2 types, savings, mixed sets)
- `AWSEC2LowCPURule` — 13 subtests (CW sentinel, threshold boundary, state filtering, CE cost skip, savings proportional)
- `AWSNATLowTrafficRule` — 12 subtests (0/0.5GB flagged, 1.0/5GB not flagged, state filtering, fields)
- `AWSSavingsPlanUnderutilizedRule` — 11 subtests (HIGH/MEDIUM boundary, coverage/cost thresholds, mixed regions)
- `AWSRDSLowCPURule` — 13 subtests (HIGH < 5%, MEDIUM 5–10%, boundary, status filter, CE cost skip, fields)
- `AWSS3PublicBucketRule` — 5 tests (ID, nil data, no public, public bucket, no-policy → not flagged, multiple public)
- `AWSSecurityGroupOpenSSHRule` — 7 tests (ID, nil data, non-admin ports, restricted CIDR, SSH, RDP, dedup)
- `AWSIAMUserWithoutMFARule` — 7 tests (ID, nil data, all MFA, API-only user skipped, console user no MFA, multiple missing)
- `AWSALBIdleRule` — 7 tests (ID, nil data, NLB ignored, inactive ignored, active ALB with traffic not flagged, idle ALB flagged, multiple)
- `AWSEC2NoSavingsPlanRule` — 7 tests (ID, nil data, no instances, zero-cost instance skipped, coverage present not flagged, no coverage flagged, distinct from SAVINGS_PLAN_UNDERUTILIZED)
- `AWSRootAccessKeyExistsRule` — 4 tests (ID, nil data, no keys, has keys with field validation)
- `AWSRootAccountMFADisabledRule` — 5 tests (ID, nil data, DataAvailable=false sentinel, MFA enabled, MFA disabled)
- `AWSCloudTrailNotMultiRegionRule` — 4 tests (ID, nil data, multi-region trail exists, no trails)
- `AWSGuardDutyDisabledRule` — 5 tests (ID, nil data, all enabled, one disabled, multiple disabled)
- `AWSConfigDisabledRule` — 5 tests (ID, nil data, all enabled, one disabled, multiple disabled)
- `AWSEBSUnencryptedRule` — 5 tests (ID, nil data, encrypted → no finding, unencrypted → HIGH, multiple)
- `AWSRDSUnencryptedRule` — 5 tests (ID, nil data, encrypted → no finding, unencrypted → CRITICAL, multiple)
- `AWSS3DefaultEncryptionMissingRule` — 5 tests (ID, nil data, enabled → no finding, missing → HIGH, multiple)
- k8s `CollectClusterData` — 4 tests with fake clientset (2 nodes + 3 namespaces, node fields, namespace names, empty cluster)
- `mergeFindings` — 12 tests (dedup, severity upgrade, savings sum, metadata merge, input immutability)
- `computeSummary` — 5 tests (severity counts, INFO handling, savings total)
- `aggregateCostSummaries` — 6 tests (nil, empty, single, sum across profiles, service breakdown merge, earliest/latest period)
- `printSummary` — 6 tests + `topFindingsBySavings` — 5 tests + `writeReportToFile` — 3 tests
- `runKubernetesInspect` — 2 tests (output fields, context flag forwarded to provider)

---

## Roadmap

- [x] NAT Gateway low-traffic detection (CloudWatch BytesOutToDestination)
- [x] Savings Plan underutilisation detection (Cost Explorer coverage API)
- [x] RDS low CPU detection (CloudWatch + Cost Explorer per-instance cost)
- [x] Kubernetes provider foundation (kubeconfig loading, node + namespace collection)
- [x] `dp kubernetes inspect` command (context, API server, node/namespace counts)
- [x] `dp kubernetes audit` command with 6 rules (single-node, overallocated, namespace limits, privileged container, public LB, pod no requests)
- [x] AWS security audit: S3, IAM MFA, root access keys, open SSH/RDP security groups
- [x] `dp aws audit security` command with table, JSON, summary, --output, and --file flags
- [x] AWS data protection audit: EBS encryption, RDS storage encryption, S3 default encryption
- [x] `dp aws audit dataprotection` command with table, JSON, summary, --output, and --file flags
- [x] `--policy` CLI flag on all four audit commands with auto-detection of `./dp.yaml`
- [x] Policy integration for cost, security, data protection, and Kubernetes engines
- [x] Threshold overrides via `rules.<ID>.params` in `dp.yaml` (EC2, RDS, NAT rules)
- [x] Minimum severity enforcement per domain via `domains.<name>.min_severity`
- [x] CI enforcement: exit code 1 on qualifying findings via `enforcement.<domain>.fail_on_severity`
- [x] Parallel region collection (errgroup + semaphore, up to 5 concurrent regions)
- [x] Parallel profile fan-out for `--all-profiles` (errgroup + semaphore, up to 3 concurrent profiles)
- [x] `dp aws audit --all` — unified cross-domain report (cost + security + dataprotection)
- [x] `AllAWSDomainsEngine` — per-domain policy enforcement + cross-domain dedup
- [x] `dp doctor` command: AWS credentials, Kubernetes connectivity, policy preflight
- [x] `dp policy validate` command
- [x] Cloud-stratified models: `internal/models/` split into `findings.go`, `aws.go`, `aws_security.go`, `kubernetes.go`
- [x] AWS namespace hardening: `aws_` rule file prefix, `AWS` struct prefix, `aws_cost` / `aws_security` / `aws_dataprotection` rulepacks
- [x] Domain-aware findings (`Domain` field on `Finding`)
- [x] Load Balancer idle detection (CloudWatch RequestCount — ALB_IDLE rule)
- [x] EC2 on-demand without Savings Plan coverage (EC2_NO_SAVINGS_PLAN rule)
- [x] CloudTrail multi-region trail check (CLOUDTRAIL_NOT_MULTI_REGION rule)
- [x] GuardDuty per-region enablement check (GUARDDUTY_DISABLED rule)
- [x] AWS Config per-region enablement check (AWS_CONFIG_DISABLED rule)
- [x] Root account MFA check (ROOT_ACCOUNT_MFA_DISABLED rule)
- [x] Coloured severity output via `--color` flag (ANSI codes, CI-safe default)
- [x] Exit code 1 on CRITICAL/HIGH findings (unconditional, independent of `--policy` enforcement)
- [x] `--all-profiles` cost aggregation: TotalCostUSD and ServiceBreakdown correctly summed across profiles
- [x] Phase 3B: Kubernetes admission/SA governance rules (K8S_POD_SECURITY_ADMISSION_NOT_ENFORCED, K8S_NAMESPACE_PSS_NOT_SET, K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT, K8S_DEFAULT_SERVICEACCOUNT_USED)
- [x] Phase 3C: Namespace classification — every K8s finding tagged `namespace_type=system|workload|cluster` in metadata
- [x] Phase 3C: `--exclude-system` flag on `dp kubernetes audit` to filter out system-namespace findings
- [x] Phase 4A: Kubernetes risk correlation — 3 compound risk chains (scores 80/60/50), `risk_chain_score` + `risk_chain_reason` metadata
- [x] Phase 4B: `summary.risk_score` — highest correlation score surfaced in `AuditSummary`; `0` when no chain fires
- [x] Phase 4C: `--min-risk-score` flag on `dp kubernetes audit` — filter findings by minimum risk chain score; `Summary.RiskScore` unaffected
- [ ] LLM summarization: findings → human-readable report
- [ ] Terraform plan analysis module
- [ ] Azure provider module
- [ ] GCP provider module
- [ ] SaaS backend with org-wide aggregation and scheduled audits
- [x] Binary releases via GoReleaser (CI pipeline + GitHub Actions)
