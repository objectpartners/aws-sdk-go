package sharedcreds

import (
	"os/user"
	"strings"
	"path/filepath"
)

type CacheProvider interface {
	Get(profile, roleArn, roleSessionName string) Cache
}

type JSONFileCacheProvider struct {
	CacheDirName string
}

func (c *JSONFileCacheProvider) Get(profile, roleArn, roleSessionName string) Cache {
	cacheKey := c.getCacheKey(profile, roleArn, roleSessionName)
	user, _ := user.Current()
	homeDir := user.HomeDir
	dir := c.CacheDirName
	if dir[:2] == "~/" {
		dir = strings.Replace(dir, "~", homeDir, 1)
	}
	return &FileCache{
		FileName: filepath.Join(dir, strings.Join([]string{cacheKey, "json"}, ".")),
	}
}

func (c *JSONFileCacheProvider) getCacheKey(profile, roleArn, roleSessionName string) string {
	arn := strings.Replace(roleArn, ":", "_", -1)
	cacheKey := strings.Join([]string{profile, arn}, "--")
	if roleSessionName != "" {
		cacheKey = strings.Join([]string{cacheKey, roleSessionName}, "--")
	}
	return cacheKey
}