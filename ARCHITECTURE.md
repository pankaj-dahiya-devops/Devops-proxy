# DevOps-Proxy Architecture

DevOps-Proxy (`dp`) is an extensible DevOps execution and analysis engine.

It is NOT an AI wrapper.

It is a deterministic DevOps auditing engine, optionally enhanced by AI summarization.

## Core Principles

1. Offline-first — all audits run without internet access (AWS SDK only, no SaaS dependency).
2. Deterministic rule engine — findings are produced by code, not by an LLM.
3. AI used only for summarization and reasoning (not implemented yet — post-MVP).
4. Engine independent from CLI — `internal/engine` has zero knowledge of cobra or output formatting.
5. SaaS compatibility from day one — all output is structured JSON; CLI is a thin rendering layer.
6. Multi-profile AWS support — `--profile`, `--all-profiles`, region discovery.
7. JSON internally, formatted output via CLI (`--report=table`, `--report=json`, `--summary`).

## Architecture Layers

```
┌─────────────────────────────────────────────────────┐
│  cmd/dp                   CLI (cobra)                │
│  - flags, wiring, output rendering                   │
│  - NO business logic                                 │
└───────────────────────┬─────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────┐
│  internal/engine          Orchestration              │
│  - AWSCostEngine          cost audit                 │
│  - AWSSecurityEngine      security audit             │
│  - AWSDataProtectionEngine  encryption audit         │
│  - RunAudit(ctx, AuditOptions) → *AuditReport        │
└──────┬──────────────────────────┬────────────────────┘
       │                          │
┌──────▼──────────┐   ┌──────────▼─────────────────────┐
│  internal/       │   │  internal/                      │
│  rulepacks/           │   │  providers/aws/                 │
│  - aws_cost (6)       │   │  - cost/     CostCollector      │
│  - aws_security (4)   │   │  - security/ SecurityCollector  │
│  - aws_dataprotection │   │  - common/   AWSClientProvider  │
│    (3)                │   │                                 │
│  - kubernetes (6)     │   │                                 │
└──────┬──────────────┘   └──────────┬─────────────────────┘
       │                              │
┌──────▼──────────────────────────────▼─────────────────┐
│  internal/rules        Rule interfaces + registry      │
│  internal/models       findings.go / aws.go /          │
│                        aws_security.go / kubernetes.go │
│  internal/policy       dp.yaml loading + ApplyPolicy   │
└───────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  internal/providers/kubernetes  Kubernetes provider  │
│  internal/llm                   AI abstraction (stub) │
│  internal/config                Config management     │
└─────────────────────────────────────────────────────┘
```

## Implemented Commands

| Command | Engine | Rules | Collectors |
|---------|--------|-------|------------|
| `dp aws audit cost` | AWSCostEngine | 6 | CostCollector (per-region EC2/EBS/NAT/RDS/ELB + Cost Explorer + SP coverage) |
| `dp aws audit security` | AWSSecurityEngine | 4 | SecurityCollector (account-level IAM/root/S3/SGs) |
| `dp aws audit dataprotection` | AWSDataProtectionEngine | 3 | CostCollector (EBS/RDS encrypted fields) + SecurityCollector (S3 encryption) |
| `dp aws audit --all` | AllAWSDomainsEngine | 13 | All three domain engines; cross-domain merge + per-domain enforcement |
| `dp kubernetes audit` | KubernetesEngine | 6 | KubeClientProvider (nodes + namespaces + LimitRanges + pods) |
| `dp kubernetes inspect` | — | — | KubeClientProvider (context, API server, nodes, namespaces) |

## Concurrency Model

**Region-level** (inside `CostCollector.CollectAll`):
- `errgroup.WithContext` + semaphore channel (capacity 5)
- One goroutine per region; `sync.Mutex` protects the shared result slice
- Fail-fast: first region error cancels all remaining regions

**Profile-level** (inside `AWSCostEngine.runAllProfiles`):
- `errgroup.WithContext` + semaphore channel (capacity 3)
- One goroutine per profile; `sync.Mutex` protects shared findings/regions/costSummary
- Fail-fast: first profile error cancels all remaining profiles
- `buildReport` (merge → policy → sort) runs sequentially after all goroutines complete

## Rule Engine Design

- Rules implement a single `Evaluate(RuleContext) []Finding` interface.
- A `RuleRegistry` holds all registered rules; `EvaluateAll` iterates them.
- Rule packs (`internal/rulepacks/`) bundle related rules and expose `New() []rules.Rule`.
- Engines register the pack, not individual rules — extensible without changing engine code.
- Rules never call AWS SDK, LLM, or CLI.

## Policy Layer

- Optional `dp.yaml` file configures per-rule overrides (disable, severity override, savings threshold).
- `policy.ApplyPolicy(findings, auditType, cfg)` filters/modifies findings post-evaluation.
- All three engines apply policy after `mergeFindings`, before `sortFindings`.
- Auto-detected from `./dp.yaml`; overridden with `--policy=<path>`.

## Finding Lifecycle

```
CollectAll → []AWSRegionData
  → evaluateAll → []Finding (raw, may have duplicates per resource)
  → mergeFindings → []Finding (one per ResourceID+Region; savings summed, severity max)
  → ApplyPolicy → []Finding (filtered by dp.yaml rules)
  → sortFindings → []Finding (CRITICAL→HIGH→MEDIUM→LOW→INFO, savings desc within tier)
  → AuditReport (JSON)
```

## Output Pipeline

```
Engine.RunAudit → *models.AuditReport
  │
  ├── --output=<path>  → writeReportToFile (JSON)
  ├── --summary        → printSummary (severity breakdown + top findings)
  ├── --report=json    → printJSON (indented JSON to stdout)
  └── default          → printTable / printSecurityTable / printDataProtectionTable
```

## Future Work

- LLM summarization: findings → human-readable report (`internal/llm` stub ready)
- Coloured severity output (lipgloss)
- Exit code 1 when CRITICAL/HIGH findings exist (separate from `--policy` enforcement)
- Load Balancer idle detection (CloudWatch RequestCount)
- EC2 on-demand without Savings Plan coverage rule
- ALB_IDLE and EC2_NO_SAVINGS_PLAN rules
- Terraform plan analysis
- Azure provider module
- GCP provider module
- SaaS backend with org-wide aggregation
- Scheduled audits
- Compliance scoring
- Binary releases via GoReleaser CI pipeline
