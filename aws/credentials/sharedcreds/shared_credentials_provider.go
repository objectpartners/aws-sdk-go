package sharedcreds

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/go-ini/ini"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws"
)

// SharedCredsProviderName provides a name of SharedCreds provider
const SharedCredsProviderName = "SharedCredentialsProvider"

var (
// ErrSharedCredentialsHomeNotFound is emitted when the user directory cannot be found.
//
// @readonly
	ErrSharedCredentialsHomeNotFound = awserr.New("UserHomeNotFound", "user home directory not found.", nil)
)

// DefaultDuration is the default amount of time in minutes that the credentials
// will be valid for.
var DefaultDuration = time.Duration(15) * time.Minute

// AssumeRoler represents the minimal subset of the STS client API used by this provider.
type AssumeRoler interface {
	AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
}

// A SharedCredentialsProvider retrieves credentials from the current user's home
// directory, and keeps track if those credentials are expired.
//
// Profile ini file example: $HOME/.aws/credentials
type SharedCredentialsProvider struct {
	credentials.Expiry

	// Path to the shared credentials file.
	//
	// If empty will look for "AWS_SHARED_CREDENTIALS_FILE" env variable. If the
	// env value is empty will default to current user's home directory.
	// Linux/OSX: "$HOME/.aws/credentials"
	// Windows:   "%USERPROFILE%\.aws\credentials"
	Filename string

	// AWS Profile to extract credentials from the shared credentials file. If empty
	// will default to environment variable "AWS_PROFILE" or "default" if
	// environment variable is also not set.
	Profile string

	// retrieved states if the credentials have been successfully retrieved.
	retrieved bool

	// The provider for where to cache STS responses, will default to using the same file cache as the AWS CLI
	CacheProvider CacheProvider

	// If the STS response cache should be used, default false
	Cache bool

	STS STSOptions
}

type STSOptions struct {
	// Expiry duration of the STS credentials. Defaults to 15 minutes if not set.
	Duration time.Duration

	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// So a ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	ExpiryWindow time.Duration

	// STS client to make assume role request with.
	Client AssumeRoler
}

// NewSharedCredentials returns a pointer to a new Credentials object
// wrapping the Profile file provider.
//
// Applies the provide functions to the provider before using it to retrieve credentials
func NewSharedCredentialsWithOptions(filename, profile string, options ...func(*SharedCredentialsProvider)) *credentials.Credentials {
	p := &SharedCredentialsProvider{
		Filename: filename,
		Profile:  profile,
		Cache: false,
		CacheProvider: &JSONFileCacheProvider{
			CacheDirName: filepath.Join("~", ".aws", "cli", "cache"),
		},
	}
	for _, option := range options {
		option(p)
	}
	return credentials.NewCredentials(p)
}

// Retrieve reads and extracts the shared credentials from the current
// users home directory.
func (p *SharedCredentialsProvider) Retrieve() (credentials.Value, error) {
	p.retrieved = false

	filename, err := p.filename()
	if err != nil {
		return credentials.Value{ProviderName: SharedCredsProviderName}, err
	}

	creds, err := loadProfile(filename, p.profile())
	if err != nil {
		return credentials.Value{ProviderName: SharedCredsProviderName}, err
	}

	if creds.RoleARN != "" {
		if creds.SourceProfile == "" {
			creds.SourceProfile = "default"
		}
		sourceCreds, err := loadProfile(filename, creds.SourceProfile)
		if err != nil {
			return credentials.Value{ProviderName: SharedCredsProviderName}, err
		}
		return p.Assume(creds, sourceCreds)
	}

	p.retrieved = true
	return creds, nil
}

func (p *SharedCredentialsProvider) Assume(credentials, sourceCredentials credentials.Value) (credentials.Value, error) {

	// Apply defaults where parameters are not set.
	if credentials.RoleSessionName == "" {
		// Try to work out a role name that will hopefully end up unique.
		credentials.RoleSessionName = fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}
	if p.STS.Duration == 0 {
		// Expire as often as AWS permits.
		p.STS.Duration = DefaultDuration
	}
	if p.STS.Client == nil {
		p.STS.Client = sts.New(session.New())
	}
	var roleOutput *sts.AssumeRoleOutput
	var err error
	if p.Cache {
		cache := p.CacheProvider.Get(credentials.SourceProfile, credentials.RoleARN, credentials.RoleSessionName)
		if !cache.IsExpired() {
			roleOutput, err = cache.Get()
		} else {
			roleOutput, err = p.STS.Client.AssumeRole(&sts.AssumeRoleInput{
				DurationSeconds: aws.Int64(int64(p.STS.Duration / time.Second)),
				RoleArn:         aws.String(credentials.RoleARN),
				RoleSessionName: aws.String(credentials.RoleSessionName),
				ExternalId:      credentials.ExternalID,
			})
			if err != nil {
				err = cache.Set(roleOutput)
			}
		}
	} else {
		roleOutput, err = p.STS.Client.AssumeRole(&sts.AssumeRoleInput{
			DurationSeconds: aws.Int64(int64(p.STS.Duration / time.Second)),
			RoleArn:         aws.String(credentials.RoleARN),
			RoleSessionName: aws.String(credentials.RoleSessionName),
			ExternalId:      credentials.ExternalID,
		})
	}

	if err != nil {
		return credentials.Value{ProviderName: SharedCredsProviderName}, err
	}

	// We will proactively generate new credentials before they expire.
	p.SetExpiration(*roleOutput.Credentials.Expiration, p.STS.ExpiryWindow)

	return credentials.Value{
		AccessKeyID:     *roleOutput.Credentials.AccessKeyId,
		SecretAccessKey: *roleOutput.Credentials.SecretAccessKey,
		SessionToken:    *roleOutput.Credentials.SessionToken,
		ProviderName:    SharedCredsProviderName,
	}, nil
}

// IsExpired returns if the shared credentials have expired.
func (p *SharedCredentialsProvider) IsExpired() bool {
	return !p.retrieved && p.Expiry.IsExpired()
}

// loadProfiles loads from the file pointed to by shared credentials filename for profile.
// The credentials retrieved from the profile will be returned or error. Error will be
// returned if it fails to read from the file, or the data is invalid.
func loadProfile(filename, profile string) (credentials.Value, error) {
	config, err := ini.Load(filename)
	if err != nil {
		return credentials.Value{ProviderName: SharedCredsProviderName}, awserr.New("SharedCredsLoad", "failed to load shared credentials file", err)
	}
	iniProfile, err := config.GetSection(profile)
	if err != nil {
		return credentials.Value{ProviderName: SharedCredsProviderName}, awserr.New("SharedCredsLoad", "failed to get profile", err)
	}

	value := credentials.Value{
		AccessKeyID:     iniProfile.Key("aws_access_key_id").String(),
		SecretAccessKey: iniProfile.Key("aws_secret_access_key").String(),
		SessionToken:    iniProfile.Key("aws_session_token").String(),
		ProviderName:    SharedCredsProviderName,
		RoleARN: iniProfile.Key("role_arn").String(),
		RoleSessionName: iniProfile.Key("role_session_name").String(),
		SourceProfile: iniProfile.Key("source_profile").String(),
		MFASerial: iniProfile.Key("mfa_serial").String(),
	}
	return validate(value, filename, profile)
}

func validate(value credentials.Value, filename, profile string) (credentials.Value, error) {
	if value.RoleARN == "" {
		if value.AccessKeyID == "" {
			return credentials.Value{ProviderName: SharedCredsProviderName}, awserr.New("SharedCredsAccessKey",
				fmt.Sprintf("shared credentials %s in %s did not contain aws_access_key_id", profile, filename),
				nil)
		}
		if value.SecretAccessKey == "" {
			return credentials.Value{ProviderName: SharedCredsProviderName}, awserr.New("SharedCredsSecret",
				fmt.Sprintf("shared credentials %s in %s did not contain aws_secret_access_key", profile, filename),
				nil)
		}
	} else {
		if value.SourceProfile == "" {
			return credentials.Value{ProviderName: SharedCredsProviderName}, awserr.New("SharedCredsSourceProfile",
				fmt.Sprintf("shared credentials %s in %s did not contain source_profile", profile, filename),
				nil)
		}
	}
	return value, nil
}

// filename returns the filename to use to read AWS shared credentials.
//
// Will return an error if the user's home directory path cannot be found.
func (p *SharedCredentialsProvider) filename() (string, error) {
	if p.Filename == "" {
		if p.Filename = os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); p.Filename != "" {
			return p.Filename, nil
		}

		homeDir := os.Getenv("HOME") // *nix
		if homeDir == "" {           // Windows
			homeDir = os.Getenv("USERPROFILE")
		}
		if homeDir == "" {
			return "", ErrSharedCredentialsHomeNotFound
		}

		p.Filename = filepath.Join(homeDir, ".aws", "credentials")
	}

	return p.Filename, nil
}

// profile returns the AWS shared credentials profile.  If empty will read
// environment variable "AWS_PROFILE". If that is not set profile will
// return "default".
func (p *SharedCredentialsProvider) profile() string {
	if p.Profile == "" {
		p.Profile = os.Getenv("AWS_PROFILE")
	}
	if p.Profile == "" {
		p.Profile = "default"
	}

	return p.Profile
}
