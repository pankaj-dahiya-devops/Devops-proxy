#!/bin/bash

echo "Creating DevOps-Proxy structure..."

mkdir -p cmd/dp
mkdir -p internal/engine
mkdir -p internal/providers/aws/cost
mkdir -p internal/providers/aws/common
mkdir -p internal/rules
mkdir -p internal/models
mkdir -p internal/llm
mkdir -p internal/config
mkdir -p docs

touch cmd/dp/main.go
touch internal/engine/engine.go
touch internal/providers/aws/common/client.go
touch internal/providers/aws/cost/collector.go
touch internal/rules/rule.go
touch internal/models/findings.go
touch internal/llm/client.go
touch internal/config/config.go
touch ARCHITECTURE.md
touch ROADMAP.md

echo "Initializing Go module..."
go mod init github.com/pankaj-dahiya-devops/Devops-proxy

echo "Done."