package common

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// DefaultAWSClientProvider is the production implementation of AWSClientProvider.
// It reads credentials from the standard AWS shared config and credentials files
// (~/.aws/config and ~/.aws/credentials) using the AWS SDK v2.
//
// Inject a custom ClientFactory via NewDefaultAWSClientProviderWithFactory to
// replace real SDK clients with mocks in unit tests.
type DefaultAWSClientProvider struct {
	factory ClientFactory
}

// NewDefaultAWSClientProvider returns a provider backed by the real AWS SDK.
func NewDefaultAWSClientProvider() *DefaultAWSClientProvider {
	return &DefaultAWSClientProvider{factory: NewClientSet}
}

// NewDefaultAWSClientProviderWithFactory returns a provider that uses f to
// create its ClientSet. Pass a mock factory in tests.
func NewDefaultAWSClientProviderWithFactory(f ClientFactory) *DefaultAWSClientProvider {
	return &DefaultAWSClientProvider{factory: f}
}

// ---------------------------------------------------------------------------
// AWSClientProvider implementation
// ---------------------------------------------------------------------------

// LoadProfile loads the AWS SDK config for the named profile and returns a
// fully populated ProfileConfig including the resolved account ID and
// initialised service clients.
//
// Pass an empty string to load the default profile.
func (p *DefaultAWSClientProvider) LoadProfile(ctx context.Context, profile string) (*ProfileConfig, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		name := profileDisplayName(profile)
		return nil, fmt.Errorf("load AWS profile %q: %w", name, err)
	}

	// Fall back to us-east-1 when the profile has no region configured so
	// that all SDK clients can be constructed successfully.
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	clients := p.factory(cfg)

	accountID, err := resolveAccountID(ctx, clients.STS)
	if err != nil {
		return nil, fmt.Errorf("resolve account ID for profile %q: %w", profileDisplayName(profile), err)
	}

	return &ProfileConfig{
		ProfileName: profileDisplayName(profile),
		AccountID:   accountID,
		Region:      cfg.Region,
		Config:      cfg,
		Clients:     clients,
	}, nil
}

// LoadAllProfiles discovers every profile defined in ~/.aws/credentials and
// ~/.aws/config, loads each one, and returns the successfully loaded set.
// Profiles that cannot be loaded (missing credentials, invalid config, etc.)
// are silently skipped so one bad profile does not block the rest.
func (p *DefaultAWSClientProvider) LoadAllProfiles(ctx context.Context) ([]*ProfileConfig, error) {
	names, err := discoverProfileNames()
	if err != nil {
		return nil, fmt.Errorf("discover AWS profiles: %w", err)
	}

	var profiles []*ProfileConfig
	for _, name := range names {
		// LoadProfile uses an empty string for the default profile.
		arg := ""
		if name != "default" {
			arg = name
		}

		pc, loadErr := p.LoadProfile(ctx, arg)
		if loadErr != nil {
			// Skip profiles that have no usable credentials.
			continue
		}
		profiles = append(profiles, pc)
	}

	return profiles, nil
}

// GetActiveRegions returns all AWS regions that are enabled (opted-in) for
// the account associated with cfg. It uses EC2 DescribeRegions, which is a
// global call and works correctly regardless of the client's home region.
func (p *DefaultAWSClientProvider) GetActiveRegions(ctx context.Context, cfg *ProfileConfig) ([]string, error) {
	out, err := cfg.Clients.EC2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		// AllRegions false (default) returns only regions the account has
		// opted into; it excludes disabled / not-subscribed regions.
		AllRegions: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("describe regions for profile %q: %w", cfg.ProfileName, err)
	}

	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		if r.RegionName != nil {
			regions = append(regions, *r.RegionName)
		}
	}
	return regions, nil
}

// ConfigForRegion returns a copy of cfg.Config with Region set to region.
// Use the returned aws.Config to construct region-scoped SDK clients for
// per-region data collection.
func (p *DefaultAWSClientProvider) ConfigForRegion(cfg *ProfileConfig, region string) aws.Config {
	regional := cfg.Config
	regional.Region = region
	return regional
}

// ---------------------------------------------------------------------------
// Package-private helpers
// ---------------------------------------------------------------------------

// profileDisplayName returns a human-readable profile identifier. An empty
// string (the default profile) is shown as "default".
func profileDisplayName(profile string) string {
	if profile == "" {
		return "default"
	}
	return profile
}

// resolveAccountID calls STS GetCallerIdentity to retrieve the numeric AWS
// account ID for the credentials currently loaded in stsClient.
func resolveAccountID(ctx context.Context, stsClient STSClient) (string, error) {
	out, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("STS GetCallerIdentity: %w", err)
	}
	if out.Account == nil {
		return "", fmt.Errorf("STS GetCallerIdentity returned nil account")
	}
	return aws.ToString(out.Account), nil
}

// discoverProfileNames reads ~/.aws/credentials and ~/.aws/config and returns
// the deduplicated list of all profile names found. "default" is always
// normalised to the string "default".
func discoverProfileNames() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}

	// ~/.aws/credentials: section headers are the bare profile name.
	credProfiles, err := parseProfilesFromFile(
		filepath.Join(home, ".aws", "credentials"),
		false, // no prefix to strip
	)
	if err != nil {
		return nil, err
	}

	// ~/.aws/config: non-default profiles are prefixed with "profile ".
	cfgProfiles, err := parseProfilesFromFile(
		filepath.Join(home, ".aws", "config"),
		true, // strip "profile " prefix
	)
	if err != nil {
		return nil, err
	}

	// Merge, preserving order and deduplicating.
	seen := make(map[string]bool)
	var all []string
	for _, name := range append(credProfiles, cfgProfiles...) {
		if name == "" {
			continue
		}
		if !seen[name] {
			seen[name] = true
			all = append(all, name)
		}
	}
	return all, nil
}

// parseProfilesFromFile scans path for INI section headers ([...]) and
// returns the profile name from each header.
//
// When stripProfilePrefix is true, the "profile " prefix used in
// ~/.aws/config is removed (e.g. "[profile staging]" → "staging").
// The "[default]" section is always returned as "default" unchanged.
//
// If the file does not exist, nil is returned without an error.
func parseProfilesFromFile(path string, stripProfilePrefix bool) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var profiles []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Section headers look like [name] or [profile name].
		if !strings.HasPrefix(line, "[") || !strings.HasSuffix(line, "]") {
			continue
		}

		name := line[1 : len(line)-1] // strip surrounding brackets

		// ~/.aws/config uses "[profile <name>]" for non-default profiles.
		if stripProfilePrefix && name != "default" {
			name = strings.TrimPrefix(name, "profile ")
		}

		profiles = append(profiles, strings.TrimSpace(name))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return profiles, nil
}
