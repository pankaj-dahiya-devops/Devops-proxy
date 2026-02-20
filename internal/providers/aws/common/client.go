package common

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// ProfileConfig is a resolved AWS profile with its SDK configuration and
// initialised service clients. It is the unit passed between provider
// functions and into the engine.
type ProfileConfig struct {
	// ProfileName is the name from ~/.aws/credentials or "default".
	ProfileName string

	// AccountID is the resolved AWS account ID for this profile (via STS).
	AccountID string

	// Region is the home region for this profile configuration.
	Region string

	// Config is the fully loaded AWS SDK v2 configuration.
	Config aws.Config

	// Clients holds initialised service clients scoped to this profile's
	// home region. Use AWSClientProvider.ConfigForRegion + NewClientSet to
	// obtain region-scoped clients for per-region collection.
	Clients *ClientSet
}

// AWSClientProvider loads AWS configurations and resolves active regions.
// It is the sole entry point for AWS credential and region management across
// the entire provider layer.
//
// Implementations must use the AWS SDK v2 only. Never call the aws CLI.
type AWSClientProvider interface {
	// LoadProfile returns a ProfileConfig for the named profile.
	// Pass an empty string to load the default profile.
	LoadProfile(ctx context.Context, profile string) (*ProfileConfig, error)

	// LoadAllProfiles returns ProfileConfigs for every profile found in
	// ~/.aws/credentials and ~/.aws/config.
	LoadAllProfiles(ctx context.Context) ([]*ProfileConfig, error)

	// GetActiveRegions returns all regions that are enabled for the account
	// associated with cfg. The list is used to drive per-region collection.
	GetActiveRegions(ctx context.Context, cfg *ProfileConfig) ([]string, error)

	// ConfigForRegion clones cfg with the target region set.
	// Use this to obtain a region-scoped aws.Config for SDK client construction.
	ConfigForRegion(cfg *ProfileConfig, region string) aws.Config
}
