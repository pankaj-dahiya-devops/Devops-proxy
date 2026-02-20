# DevOps-Proxy Architecture

DevOps-Proxy (dp) is an extensible DevOps execution and analysis engine.

It is NOT an AI wrapper.

It is a deterministic DevOps auditing engine enhanced by AI.

## Core Principles

1. Offline-first.
2. Deterministic rule engine.
3. AI used only for summarization and reasoning.
4. Engine independent from CLI.
5. SaaS compatibility from day one.
6. Multi-profile AWS support.

## MVP Focus

AWS Cost Audit (FinOps).

## Architecture Layers

- Engine Layer
- Provider Layer (AWS first)
- Rule Engine
- Models
- LLM (optional enhancement)
- CLI interface

## AWS Cost MVP Must:

- Use AWS SDK v2 (NOT aws CLI)
- Support multiple AWS profiles
- Collect:
  - Cost Explorer (30 days)
  - EC2 instances
  - EBS volumes
  - NAT Gateways
  - RDS
  - Load Balancers
  - Savings Plan coverage
- Convert all raw data to structured models
- Apply deterministic rules
- Return structured JSON findings

## Future Expansion

- AWS Security
- Kubernetes
- Terraform
- Azure
- GCP
- SaaS backend
- Org-wide aggregation