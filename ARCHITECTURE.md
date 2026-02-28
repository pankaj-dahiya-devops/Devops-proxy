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
7. JSON internally, formatted output via CLI (`--output table|json`, `--summary`).

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  cmd/dp                        CLI (cobra)                       │
│  - flags, wiring, output rendering                               │
│  - NO business logic                                             │
└───────────────────────┬─────────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────────┐
│  internal/engine               Orchestration                     │
│                                                                  │
│  AWS engines:                  Kubernetes engine:                │
│  - AWSCostEngine               - KubernetesEngine                │
│  - AWSSecurityEngine             + correlateRiskChains (6 chains)│
│  - AWSDataProtectionEngine       + buildAttackPaths (5 paths)    │
│  - AllAWSDomainsEngine           + buildRiskChains               │
│                                  + namespace classification       │
│  RunAudit(ctx, Options) → *AuditReport                           │
└──────┬──────────────────────────────┬───────────────────────────┘
       │                              │
┌──────▼──────────────┐   ┌───────────▼────────────────────────────┐
│  internal/rulepacks │   │  internal/providers/                    │
│                     │   │                                         │
│  aws_cost (8 rules) │   │  aws/common/  AWSClientProvider         │
│  aws_security       │   │  aws/cost/    CostCollector             │
│    (8 rules)        │   │  aws/security/ SecurityCollector        │
│  aws_dataprotection │   │  aws/eks/     DefaultEKSCollector       │
│    (3 rules)        │   │  kubernetes/  KubeClientProvider        │
│  kubernetes_core    │   │               CollectClusterData        │
│    (16 rules)       │   │                                         │
│  kubernetes_eks     │   └─────────────────────────────────────────┘
│    (6 rules)        │
└──────┬──────────────┘
       │
┌──────▼──────────────────────────────────────────────────────────┐
│  internal/rules         Rule interfaces + registry               │
│  internal/models        findings.go / aws.go / kubernetes.go     │
│  internal/policy        dp.yaml loading + ApplyPolicy            │
└─────────────────────────────────────────────────────────────────┘
```

## Implemented Commands

| Command | Engine | Rules | Collectors |
|---------|--------|-------|------------|
| `dp aws audit cost` | AWSCostEngine | 8 | CostCollector (EC2/EBS/NAT/RDS/ELB+CW + Cost Explorer + SP coverage) |
| `dp aws audit security` | AWSSecurityEngine | 8 | SecurityCollector (IAM/root/S3/SGs + CloudTrail + GuardDuty + Config) |
| `dp aws audit dataprotection` | AWSDataProtectionEngine | 3 | CostCollector (EBS/RDS encrypted fields) + SecurityCollector (S3) |
| `dp aws audit --all` | AllAWSDomainsEngine | 19 | All three domain engines; cross-domain merge + per-domain enforcement |
| `dp kubernetes audit` | KubernetesEngine | 22 | KubeClientProvider (nodes/namespaces/LimitRanges/pods/SAs) + EKSCollector |
| `dp kubernetes inspect` | — | — | KubeClientProvider (context, API server, nodes, namespaces) |

## Concurrency Model

**Region-level** (inside `CostCollector.CollectAll`):
- `errgroup.WithContext` + semaphore channel (capacity 5)
- One goroutine per region; `sync.Mutex` protects the shared result slice
- Fail-fast: first region error cancels all remaining regions

**Profile-level** (inside `AWSCostEngine.runAllProfiles`):
- `errgroup.WithContext` + semaphore channel (capacity 3)
- One goroutine per profile; `sync.Mutex` protects shared findings/regions/allCostSummaries
- CostSummaries aggregated via `aggregateCostSummaries` (sum TotalCostUSD, merge ServiceBreakdown)
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
- All engines apply policy after `mergeFindings`, before `sortFindings`.
- Auto-detected from `./dp.yaml`; overridden with `--policy=<path>`.

## Finding Lifecycle

```
CollectAll → raw data
  → EvaluateAll → []Finding (raw, may have duplicates per resource)
  → mergeFindings → []Finding (one per ResourceID+Region; savings summed, severity max)
  → annotateNamespaceType → stamp namespace_type=system|workload|cluster on each finding
  → [excludeSystemFindings] → optional: remove system-namespace findings
  → correlateRiskChains → annotate risk_chain_score + risk_chain_reason on participating findings
  → buildAttackPaths → []AttackPath (multi-layer compound paths; cluster + namespace scoped)
  → [filterByMinRiskScore] → optional: retain only findings at or above min score
  → ApplyPolicy → []Finding (filtered by dp.yaml rules)
  → sortFindings → []Finding (CRITICAL→HIGH→MEDIUM→LOW→INFO, savings desc within tier)
  → AuditReport (JSON)
```

## Output Pipeline

```
Engine.RunAudit → *models.AuditReport
  │
  ├── --file=<path>    → write full JSON report to file
  ├── --summary        → printSummary (severity breakdown + top findings)
  ├── --output=json    → encodeJSON (indented JSON to stdout)
  ├── --color          → ANSI severity coloring in table output (opt-in, CI-safe default)
  └── default          → renderTable (colored bool)
```

Exit code 1 is returned unconditionally when any CRITICAL or HIGH finding exists.

## Kubernetes Audit: Correlation Engine

The correlation engine lives in `internal/engine/kubernetes_correlation.go` and runs as a post-merge, pre-policy pass on the Kubernetes finding set.

### Phase Overview

| Phase | Feature | File |
|-------|---------|------|
| 3C | Namespace classification (system/workload/cluster) | kubernetes.go |
| 4A | Risk chains 1–3 (scores 50/60/80) | kubernetes_correlation.go |
| 4B | `Summary.RiskScore` | kubernetes.go |
| 4C | `--min-risk-score` filtering | kubernetes_correlation.go |
| 5C | Risk chains 4–6 (scores 90/85/95) | kubernetes_correlation.go |
| 5D | `--show-risk-chains`; `buildRiskChains` | kubernetes_correlation.go |
| 6 | `buildAttackPaths` — PATH 1/2/3 | kubernetes_correlation.go |
| 6.1 | Namespace-scoped dual-index for attack paths | kubernetes_correlation.go |
| 6.2 | Strict rule-scoped filtering (primary-only collection) | kubernetes_correlation.go |
| 7A | PATH 4 — EKS Control Plane Exposure | kubernetes_correlation.go |
| 7B | PATH 5 — Cross-Cloud Identity Escalation | kubernetes_correlation.go |

### Namespace Classification

Every finding is stamped with `Metadata["namespace_type"]`:

| Value | When |
|-------|------|
| `"system"` | Namespace is `kube-system`, `kube-public`, or `kube-node-lease` |
| `"workload"` | Non-empty namespace not in system set |
| `"cluster"` | No namespace (nodes, EKS rules, cluster-level rules) |

`resolveNamespaceForFinding(f)` extracts the namespace string:
1. `ResourceType == K8S_NAMESPACE` → `ResourceID`
2. `Metadata["namespace"].(string)`
3. `""` (cluster-scoped)

### Risk Chain Correlation

`correlateRiskChains(findings)` annotates findings participating in compound risk patterns. When multiple chains apply, the highest score wins. Severity and sort order are never changed.

| Chain | Score | Scope | Condition | Reason |
|-------|-------|-------|-----------|--------|
| 6 | 95 | global | `EKS_OIDC_PROVIDER_NOT_ASSOCIATED` + any HIGH finding | "Cluster lacks OIDC provider and has high-risk workload findings." |
| 4 | 90 | global | `EKS_NODE_ROLE_OVERPERMISSIVE` + `K8S_SERVICE_PUBLIC_LOADBALANCER` | "Public service exposed in cluster with over-permissive node IAM role." |
| 5 | 85 | namespace | `EKS_SERVICEACCOUNT_NO_IRSA` + `K8S_DEFAULT_SERVICEACCOUNT_USED` | "Default service account used without IRSA." |
| 1 | 80 | namespace | `K8S_SERVICE_PUBLIC_LOADBALANCER` + (`K8S_POD_RUN_AS_ROOT` OR `K8S_POD_CAP_SYS_ADMIN`) | "Public service exposes privileged workload" |
| 2 | 60 | namespace | `K8S_DEFAULT_SERVICEACCOUNT_USED` + `K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT` | "Default service account with auto-mounted token" |
| 3 | 50 | global | `K8S_CLUSTER_SINGLE_NODE` + any CRITICAL finding | "Single-node cluster with critical pod security violation" |

### Risk Chain vs Attack Path Distinction

| Aspect | Risk Chain | Attack Path |
|--------|-----------|-------------|
| Scope | Annotates **individual findings** | Describes a **multi-layer attacker journey** |
| Output | `Metadata["risk_chain_score"]` on each finding | `[]AttackPath` in `Summary.AttackPaths` |
| Grouping | Findings sharing same (score, reason) pair | All findings in path grouped under one `AttackPath` |
| RiskScore contribution | Fallback when no attack path fires | Always wins when a path is detected |
| Enabled by | `ShowRiskChains=true` (both) | `ShowRiskChains=true` (both) |

### Attack Path Correlation Flow

`buildAttackPaths(findings)` detects multi-layer compound attack paths using a **dual detection/collection index** design.

#### Dual-Index Design

**Detection index** (expanded — uses `ruleIDsForFinding`):
- `detectNS[namespace][ruleID]` — namespace-scoped findings, expanded to include merged rule IDs from `Metadata["rules"]`
- `detectCluster[ruleID]` — cluster-scoped findings, expanded

Rationale: `mergeFindings` may merge same-resource findings; the relevant rule ID might be a non-primary merged rule. Expanded detection prevents false negatives.

**Collection index** (primary-only — uses `f.RuleID` only):
- `collectNS[namespace][ruleID]=[]findingID`
- `collectCluster[ruleID]=[]findingID`

Rationale: `AttackPath.FindingIDs` must contain only findings directly scoped to the path definition. Only the primary `f.RuleID` is indexed, so unrelated co-located findings never appear.

#### Five Attack Paths

| Path | Score | Scope | Trigger Conditions | Allowed Primary Rule IDs |
|------|-------|-------|-------------------|--------------------------|
| **PATH 1** | **98** | Per-namespace | `K8S_SERVICE_PUBLIC_LOADBALANCER` + (`K8S_POD_RUN_AS_ROOT` OR `K8S_POD_CAP_SYS_ADMIN`) + (`EKS_SERVICEACCOUNT_NO_IRSA` OR `K8S_DEFAULT_SERVICEACCOUNT_USED`); optional cluster: `EKS_NODE_ROLE_OVERPERMISSIVE` | `K8S_SERVICE_PUBLIC_LOADBALANCER`, `K8S_POD_RUN_AS_ROOT`, `K8S_POD_CAP_SYS_ADMIN`, `EKS_SERVICEACCOUNT_NO_IRSA`, `K8S_DEFAULT_SERVICEACCOUNT_USED`, `EKS_NODE_ROLE_OVERPERMISSIVE` |
| **PATH 5** | **96** | Per-namespace | `K8S_SERVICE_PUBLIC_LOADBALANCER` + (`K8S_POD_RUN_AS_ROOT` OR `K8S_POD_CAP_SYS_ADMIN`) + (`EKS_SERVICEACCOUNT_NO_IRSA` OR `K8S_DEFAULT_SERVICEACCOUNT_USED` OR `K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT`); cluster: (`EKS_NODE_ROLE_OVERPERMISSIVE` OR `EKS_IAM_ROLE_WILDCARD`) | `K8S_SERVICE_PUBLIC_LOADBALANCER`, `K8S_POD_RUN_AS_ROOT`, `K8S_POD_CAP_SYS_ADMIN`, `EKS_SERVICEACCOUNT_NO_IRSA`, `K8S_DEFAULT_SERVICEACCOUNT_USED`, `K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT`, `EKS_NODE_ROLE_OVERPERMISSIVE`, `EKS_IAM_ROLE_WILDCARD` |
| **PATH 4** | **94** | Cluster | `EKS_PUBLIC_ENDPOINT_ENABLED` + (`EKS_NODE_ROLE_OVERPERMISSIVE` OR `EKS_IAM_ROLE_WILDCARD`) + `EKS_CONTROL_PLANE_LOGGING_DISABLED` | `EKS_PUBLIC_ENDPOINT_ENABLED`, `EKS_NODE_ROLE_OVERPERMISSIVE`, `EKS_IAM_ROLE_WILDCARD`, `EKS_CONTROL_PLANE_LOGGING_DISABLED` |
| **PATH 2** | **92** | Per-namespace | `K8S_DEFAULT_SERVICEACCOUNT_USED` + `K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT` + `EKS_SERVICEACCOUNT_NO_IRSA`; cluster: `EKS_OIDC_PROVIDER_NOT_ASSOCIATED` | `K8S_DEFAULT_SERVICEACCOUNT_USED`, `K8S_SERVICEACCOUNT_TOKEN_AUTOMOUNT`, `EKS_SERVICEACCOUNT_NO_IRSA`, `EKS_OIDC_PROVIDER_NOT_ASSOCIATED` |
| **PATH 3** | **90** | Cluster | `EKS_ENCRYPTION_DISABLED` + `EKS_CONTROL_PLANE_LOGGING_DISABLED` + `K8S_CLUSTER_SINGLE_NODE` | `EKS_ENCRYPTION_DISABLED`, `EKS_CONTROL_PLANE_LOGGING_DISABLED`, `K8S_CLUSTER_SINGLE_NODE` |

#### Execution Order and Sorting

1. Build detection index (expanded) + collection index (primary-only) from the input findings.
2. Evaluate PATH 1 (per qualifying namespace → N entries at score 98).
3. Evaluate PATH 5 (per qualifying namespace → M entries at score 96).
4. Evaluate PATH 2 (per qualifying namespace → K entries at score 92).
5. Evaluate PATH 3 (cluster-scoped → 0 or 1 entry at score 90).
6. Evaluate PATH 4 (cluster-scoped → 0 or 1 entry at score 94).
7. `sort.Slice` by descending score → final sorted `[]AttackPath`.

#### Scoping Rules

- **Per-namespace paths (PATH 1, PATH 5, PATH 2)**: conditions are evaluated per namespace; one `AttackPath` entry per qualifying namespace; findings from one namespace never contaminate another's path.
- **Cluster-scoped paths (PATH 3, PATH 4)**: all conditions use the cluster detection index; exactly one entry total when triggered; no namespace iteration.
- Cluster-level findings (e.g. `EKS_NODE_ROLE_OVERPERMISSIVE`) appended per PATH 1 and PATH 5 entry from the cluster collection index (deduplicated).

#### RiskScore Hierarchy

```
if any AttackPath detected:
    Summary.RiskScore = max(AttackPath.Score)     # always >= 90
else:
    Summary.RiskScore = max(risk_chain_score)     # 0..95
```

Computed pre-policy, pre-filter so `Summary.RiskScore` always reflects true cluster risk.

## Engine Layering Philosophy

1. **Providers** — data only; no analysis
2. **Rules** — deterministic evaluation; no I/O
3. **Engine** — orchestrates collect → evaluate → merge → correlate → filter → sort → report
4. **CLI** — renders the report; no business logic
5. **LLM** — optional summarization only; never produces findings

This layering ensures the engine can be tested in isolation, reused as a library, and extended without touching the CLI.

## Future Work

- LLM summarization: findings → human-readable report (`internal/llm` stub ready)
- Terraform plan analysis
- Azure provider module
- GCP provider module
- SaaS backend with org-wide aggregation
- Scheduled audits
- Compliance scoring
