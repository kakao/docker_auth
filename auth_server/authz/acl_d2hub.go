package authz

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang/glog"
)

const (
	adminOrgName = "d2hub"
)

type ACLD2hubConfig struct {
	D2HubURL string `yaml:"d2hub_url"`
}

type aclD2hubAuthorizer struct {
	config *ACLD2hubConfig
}

func NewACLD2hubAuthorizer(c *ACLD2hubConfig) (Authorizer, error) {
	return &aclD2hubAuthorizer{
		config: c,
	}, nil
}

func (da *aclD2hubAuthorizer) Authorize(ai *AuthRequestInfo) ([]string, error) {
	glog.Infof("Authorize - AuthRequestInfo: %s\n", ai.String())
	authActions := []string{}
	for _, action := range ai.Actions {
		if action == "pull" {
			if err := da.checkPullACL(ai); err == nil {
				authActions = append(authActions, "pull")
			}
		}
		if action == "push" {
			if err := da.checkPushACL(ai); err == nil {
				authActions = append(authActions, "push")
			}
		}
	}
	return authActions, nil
}

func (da *aclD2hubAuthorizer) Stop() {

}

func (da *aclD2hubAuthorizer) Name() string {
	return "D2Hub ACL"
}

func (da *aclD2hubAuthorizer) checkPullACL(ai *AuthRequestInfo) error {
	glog.V(2).Infof("Check Pull ACL - AuthRequestInfo: %s\n", ai.String())
	orgName, repoName, err := parseImageName(ai.Name)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/auth/orgs/%s/repos/%s/pull", da.config.D2HubURL, orgName, repoName), nil)
	if err != nil {
		return err
	}

	if ai.Account != "" && ai.Password.String() != "" {
		req.SetBasicAuth(ai.Account, string(ai.Password))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("status code isn't 200")
	}
	return nil
}

func (da *aclD2hubAuthorizer) checkPushACL(ai *AuthRequestInfo) error {
	glog.V(2).Infof("Check Push ACL - AuthRequestInfo: %s\n", ai.String())
	if ai.Account == "" || ai.Password.String() == "" {
		return errors.New("Not found basic authorize info")
	}

	orgName, repoName, err := parseImageName(ai.Name)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/auth/orgs/%s/repos/%s/push", da.config.D2HubURL, orgName, repoName), nil)
	if err != nil {
		glog.Error(err)
		return err
	}
	req.SetBasicAuth(ai.Account, string(ai.Password))

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		glog.Error(err)
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		return errors.New("status code isn't 201")
	}
	return nil
}

func parseImageName(imageName string) (string, string, error) {
	if imageName == "" {
		return "", "", errors.New("imageName is empty")
	}
	if strings.Contains(imageName, "/") {
		names := strings.Split(imageName, "/")
		return names[0], names[1], nil
	}
	return adminOrgName, imageName, nil
}
