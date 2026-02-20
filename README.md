# DevOps Proxy (dp)

An extensible DevOps execution engine with deterministic rule-based analysis and optional AI summarisation.

Currently implements: **AWS cost audit** — multi-profile, multi-region, CloudWatch-backed.

---

## Overview

`dp` collects raw AWS resource data, runs a deterministic rule engine to detect waste and inefficiencies, and returns structured findings with severity rankings and estimated monthly savings.

- Multi-profile and multi-region out of the box
- Rule engine works fully offline — no LLM required
- Real CloudWatch CPU data for EC2 analysis
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

```bash
# Audit default profile, table output
./dp aws audit cost

# Named profile, JSON output
./dp aws audit cost --profile staging --report=json

# All configured profiles
./dp aws audit cost --all-profiles

# Explicit regions, 14-day lookback
./dp aws audit cost --profile prod --region us-east-1 --region eu-west-1 --days 14
```

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--profile` | string | `""` | Named AWS profile (empty = default/env credentials) |
| `--all-profiles` | bool | `false` | Audit every profile in `~/.aws/config` |
| `--region` | []string | `nil` | Explicit regions; omit to auto-discover active regions |
| `--days` | int | `30` | Lookback window for cost and CloudWatch metric queries |
| `--report` | string | `table` | Output format: `table` or `json` |

---

## Example Output

### Table

```
Profile: default       Account: 123456789012  Regions: 3  Findings: 3  Est. Savings: $48.00/mo

RESOURCE ID                                REGION           SEVERITY    SAVINGS/MO
----------------------------------------------------------------------------------
i-0a1b2c3d4e5f67890                        us-east-1        MEDIUM      $30.00
vol-0abc1234def567890                      us-east-1        MEDIUM      $16.00
vol-0def5678abc123456                      eu-west-1        LOW         $2.00
```

### JSON

```json
{
  "report_id": "audit-1740000000000000000",
  "audit_type": "cost",
  "profile": "default",
  "account_id": "123456789012",
  "regions": ["us-east-1", "eu-west-1"],
  "summary": {
    "total_findings": 3,
    "medium_findings": 2,
    "low_findings": 1,
    "total_estimated_monthly_savings_usd": 48.00
  },
  "findings": [
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
  engine.go        Engine interface, AuditOptions, AuditType
  default.go       DefaultEngine: orchestrates collection → rules → merge → sort → report

internal/providers/aws/
  common/          AWSClientProvider: profile loading, region discovery
  cost/            CostCollector: EC2, EBS, NAT, RDS, ELB, Savings Plan, Cost Explorer

internal/rules/
  rule.go          Rule interface, RuleContext, RuleRegistry interface
  registry.go      DefaultRuleRegistry
  ec2_low_cpu.go   EC2_LOW_CPU: running instances with avg CPU < 10% (CloudWatch)
  ebs_unattached.go  EBS_UNATTACHED: volumes in "available" state
  ebs_gp2_legacy.go  EBS_GP2_LEGACY: gp2 volumes that should migrate to gp3

internal/models/
  findings.go      Finding, AuditReport, AuditSummary, all resource types
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

### Current rules

| Rule ID | Trigger | Severity | Savings estimate |
|---------|---------|----------|-----------------|
| EC2_LOW_CPU | avg CPU > 0% and < 10% over lookback period | MEDIUM | $30/mo placeholder |
| EBS_UNATTACHED | volume state == "available", not attached | MEDIUM | SizeGB × $0.08/mo |
| EBS_GP2_LEGACY | volume type == "gp2" | LOW | SizeGB × $0.02/mo |

### Test coverage

51 unit tests across rule engine and engine core:
- `EBSUnattachedRule` — 9 subtests (trigger logic, savings calculation, field validation)
- `EBSGP2LegacyRule` — 10 subtests (all non-gp2 types, savings, mixed sets)
- `EC2LowCPURule` — 11 subtests (CW sentinel, threshold boundary, state filtering)
- `mergeFindings` — 12 tests (dedup, severity upgrade, savings sum, metadata merge, input immutability)
- `computeSummary` — 5 tests (severity counts, INFO handling, savings total)

---

## Roadmap

- [ ] NAT Gateway high-transfer detection (CloudWatch BytesOutToDestination)
- [ ] Load Balancer idle detection (CloudWatch RequestCount)
- [ ] EC2 on-demand without Savings Plan coverage
- [ ] RDS idle instance detection
- [ ] Savings Plan optimisation recommendations
- [ ] Parallel region/profile collection (errgroup)
- [ ] Exit code 1 on CRITICAL/HIGH findings (CI integration)
- [ ] `--output-file` flag for JSON reports
- [ ] Terraform plan analysis module
- [ ] Kubernetes cluster cost intelligence
- [ ] Azure / GCP provider modules
- [ ] SaaS backend with org-wide aggregation and scheduled audits
