# DevOps Proxy (dp)

An extensible DevOps execution engine with deterministic rule-based analysis and optional AI summarisation.

Currently implements: **AWS cost audit**, **AWS security audit**, and **AWS data protection audit** — multi-profile, multi-region, CloudWatch-backed.

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

## Installation

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
./dp aws audit cost --profile staging --report=json

# All configured profiles
./dp aws audit cost --all-profiles

# Explicit regions, 14-day lookback
./dp aws audit cost --profile prod --region us-east-1 --region eu-west-1 --days 14

# Compact summary to stdout, also save full JSON report to file
./dp aws audit cost --profile prod --summary --output report.json

# Table output to stdout and full JSON saved to file
./dp aws audit cost --output /tmp/audit.json
```

#### Flags (`dp aws audit cost`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | Named AWS profile (empty = default/env credentials) |
| `--all-profiles` | bool | `false` | Audit every profile in `~/.aws/config` |
| `--region` | []string | `nil` | Explicit regions; omit to auto-discover active regions |
| `--days` | int | `30` | Lookback window for cost and CloudWatch metric queries |
| `--report` | string | `table` | Output format: `table` or `json` |
| `--summary` | bool | `false` | Print compact summary: totals, severity breakdown, top-5 findings |
| `--output` | string | `""` | Write full JSON report to file (does not suppress stdout output) |

### AWS security audit

```bash
# Audit default profile, table output
./dp aws audit security

# Named profile, JSON output
./dp aws audit security --profile staging --report=json

# All configured profiles
./dp aws audit security --all-profiles

# Specific regions with compact summary
./dp aws audit security --region us-east-1 --region eu-west-1 --summary

# Save full JSON report to file
./dp aws audit security --output security-report.json
```

#### Flags (`dp aws audit security`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | Named AWS profile (empty = default/env credentials) |
| `--all-profiles` | bool | `false` | Audit every profile in `~/.aws/config` |
| `--region` | []string | `nil` | Explicit regions; omit to auto-discover active regions |
| `--report` | string | `table` | Output format: `table` or `json` |
| `--summary` | bool | `false` | Print compact summary: totals, severity breakdown, top-5 findings |
| `--output` | string | `""` | Write full JSON report to file (does not suppress stdout output) |

### AWS data protection audit

```bash
# Audit default profile, table output
./dp aws audit dataprotection

# Named profile, JSON output
./dp aws audit dataprotection --profile staging --report=json

# All configured profiles
./dp aws audit dataprotection --all-profiles

# Specific regions with compact summary
./dp aws audit dataprotection --region us-east-1 --region eu-west-1 --summary

# Save full JSON report to file
./dp aws audit dataprotection --output dp-report.json
```

#### Flags (`dp aws audit dataprotection`)

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | Named AWS profile (empty = default/env credentials) |
| `--all-profiles` | bool | `false` | Audit every profile in `~/.aws/config` |
| `--region` | []string | `nil` | Explicit regions; omit to auto-discover active regions |
| `--report` | string | `table` | Output format: `table` or `json` |
| `--summary` | bool | `false` | Print compact summary: totals, severity breakdown, top-5 findings |
| `--output` | string | `""` | Write full JSON report to file (does not suppress stdout output) |

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
  default.go          DefaultEngine: orchestrates cost collection → rules → merge → sort → report
  security.go         DefaultSecurityEngine: orchestrates security collection → rules → report
  dataprotection.go   DefaultDataProtectionEngine: EBS/RDS (cost collector) + S3 (security collector)

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
  rule.go                        Rule interface, RuleContext, RuleRegistry interface
  registry.go                    DefaultRuleRegistry
  ec2_low_cpu.go                 EC2_LOW_CPU: running instances with avg CPU < 10%
  ebs_unattached.go              EBS_UNATTACHED: volumes in "available" state
  ebs_gp2_legacy.go              EBS_GP2_LEGACY: gp2 volumes that should migrate to gp3
  nat_low_traffic.go             NAT_LOW_TRAFFIC: gateways with < 1 GB traffic
  savings_plan_underutilized.go  SAVINGS_PLAN_UNDERUTILIZED: SP coverage < 60%
  rds_low_cpu.go                 RDS_LOW_CPU: available instances with avg CPU < 10%
  root_access_key.go             ROOT_ACCESS_KEY: root account has active access keys
  s3_public_bucket.go            S3_PUBLIC_BUCKET: bucket lacks full public access block
  sg_open_ssh.go                 SG_OPEN_SSH: security group exposes SSH/RDP to 0.0.0.0/0
  iam_user_no_mfa.go             IAM_USER_NO_MFA: console IAM user has no MFA device
  ebs_unencrypted.go             EBS_UNENCRYPTED: EBS volume not encrypted at rest
  rds_unencrypted.go             RDS_UNENCRYPTED: RDS instance storage not encrypted
  s3_default_encryption_missing.go  S3_DEFAULT_ENCRYPTION_MISSING: bucket has no default SSE

internal/rulepacks/cost/
  pack.go          New() []rules.Rule — all 6 cost rules

internal/rulepacks/security/
  pack.go          New() []rules.Rule — all 4 security rules

internal/rulepacks/dataprotection/
  pack.go          New() []rules.Rule — 3 data-protection rules (RDS, EBS, S3)

internal/models/
  findings.go      Finding, AuditReport, AuditSummary, all resource types
  security.go      S3Bucket, SecurityGroupRule, IAMUser, RootAccountInfo, SecurityData
```

### Engine pipeline

```
LoadProfile(s)
  → CollectAll (EC2 + CloudWatch, EBS, NAT, RDS, ELB, Savings Plan, Cost Explorer)
  → EvaluateAll (rule engine, per region)
  → mergeFindings (group by ResourceID+Region: highest severity, summed savings)
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

### Security rules

| Rule ID | Trigger | Severity |
|---------|---------|----------|
| ROOT_ACCESS_KEY | Root account has ≥ 1 active access key (IAM GetAccountSummary) | CRITICAL |
| S3_PUBLIC_BUCKET | `GetBucketPolicyStatus` `IsPublic == true`; no-policy buckets → NOT flagged | HIGH |
| SG_OPEN_SSH | Security group allows port 22 or 3389 from 0.0.0.0/0 or ::/0 | HIGH |
| IAM_USER_NO_MFA | Console IAM user (`HasLoginProfile == true`) with no MFA device | MEDIUM |

### Data protection rules

| Rule ID | Trigger | Severity |
|---------|---------|----------|
| RDS_UNENCRYPTED | RDS instance `StorageEncrypted == false` | CRITICAL |
| EBS_UNENCRYPTED | EBS volume `Encrypted == false` | HIGH |
| S3_DEFAULT_ENCRYPTION_MISSING | S3 bucket has no server-side encryption configuration | HIGH |

### Test coverage

99 unit tests across rule engine, data-protection rules, security rules, k8s provider, engine core, and CLI:
- `EBSUnattachedRule` — 9 subtests (trigger logic, savings calculation, field validation)
- `EBSGP2LegacyRule` — 10 subtests (all non-gp2 types, savings, mixed sets)
- `EC2LowCPURule` — 13 subtests (CW sentinel, threshold boundary, state filtering, CE cost skip, savings proportional)
- `NATLowTrafficRule` — 12 subtests (0/0.5GB flagged, 1.0/5GB not flagged, state filtering, fields)
- `SavingsPlanUnderutilizedRule` — 11 subtests (HIGH/MEDIUM boundary, coverage/cost thresholds, mixed regions)
- `RDSLowCPURule` — 13 subtests (HIGH < 5%, MEDIUM 5–10%, boundary, status filter, CE cost skip, fields)
- `S3PublicBucketRule` — 5 tests (ID, nil data, no public, public bucket, no-policy → not flagged, multiple public)
- `SecurityGroupOpenSSHRule` — 7 tests (ID, nil data, non-admin ports, restricted CIDR, SSH, RDP, dedup)
- `IAMUserWithoutMFARule` — 7 tests (ID, nil data, all MFA, API-only user skipped, console user no MFA, multiple missing)
- `RootAccessKeyExistsRule` — 4 tests (ID, nil data, no keys, has keys with field validation)
- `EBSUnencryptedRule` — 5 tests (ID, nil data, encrypted → no finding, unencrypted → HIGH, multiple)
- `RDSUnencryptedRule` — 5 tests (ID, nil data, encrypted → no finding, unencrypted → CRITICAL, multiple)
- `S3DefaultEncryptionMissingRule` — 5 tests (ID, nil data, enabled → no finding, missing → HIGH, multiple)
- k8s `CollectClusterData` — 4 tests with fake clientset (2 nodes + 3 namespaces, node fields, namespace names, empty cluster)
- `mergeFindings` — 12 tests (dedup, severity upgrade, savings sum, metadata merge, input immutability)
- `computeSummary` — 5 tests (severity counts, INFO handling, savings total)
- `printSummary` — 6 tests + `topFindingsBySavings` — 5 tests + `writeReportToFile` — 3 tests
- `runKubernetesInspect` — 2 tests (output fields, context flag forwarded to provider)

---

## Roadmap

- [x] NAT Gateway low-traffic detection (CloudWatch BytesOutToDestination)
- [x] Savings Plan underutilisation detection (Cost Explorer coverage API)
- [x] RDS low CPU detection (CloudWatch + Cost Explorer per-instance cost)
- [x] Kubernetes provider foundation (kubeconfig loading, node + namespace collection)
- [x] `dp kubernetes inspect` command (context, API server, node/namespace counts)
- [x] AWS security audit: S3, IAM MFA, root access keys, open SSH/RDP security groups
- [x] `dp aws audit security` command with table, JSON, summary, and --output flag
- [x] AWS data protection audit: EBS encryption, RDS storage encryption, S3 default encryption
- [x] `dp aws audit dataprotection` command with table, JSON, summary, and --output flag
- [ ] Load Balancer idle detection (CloudWatch RequestCount)
- [ ] EC2 on-demand without Savings Plan coverage
- [ ] Parallel region/profile collection (errgroup)
- [ ] Exit code 1 on CRITICAL/HIGH findings (CI integration)
- [ ] Terraform plan analysis module
- [ ] Kubernetes cluster cost intelligence (rule pack + engine integration)
- [ ] Azure / GCP provider modules
- [ ] SaaS backend with org-wide aggregation and scheduled audits
