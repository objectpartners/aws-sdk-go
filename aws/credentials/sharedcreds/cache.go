package sharedcreds

import (
	"github.com/aws/aws-sdk-go/service/sts"
	"io/ioutil"
	"encoding/json"
)

type Cache interface {
	Get() (*sts.AssumeRoleOutput, error)
	IsExpired() bool
	Set(response *sts.AssumeRoleOutput) error
}

type FileCache struct {
	FileName string
}

func (c *FileCache) Get() (*sts.AssumeRoleOutput, error) {
	data, err := ioutil.ReadFile(c.FileName)
	if err != nil {
		return nil, err
	}
	var response sts.AssumeRoleOutput
	err = json.Unmarshal(data, &response)
	return &response, err
}

func (c *FileCache) IsExpired() bool {
	return true
}

func (c *FileCache) Set(response *sts.AssumeRoleOutput) error {
	data, err := json.Marshal(*response)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(c.FileName, data, 0644)
	return err
}