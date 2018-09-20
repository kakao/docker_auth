package authn

type D2hubAuthConfig struct {
	D2HubURL string `yaml:"d2hub_url"`
}

type D2hubAuth struct {
	config *D2hubAuthConfig
}

func NewD2hubAuth(c *D2hubAuthConfig) (*D2hubAuth, error) {
	return &D2hubAuth{config: c}, nil
}

func (da *D2hubAuth) Authenticate(user string, password PasswordString) (bool, error) {
	return true, nil
}

func (da *D2hubAuth) Stop() {
}

func (da *D2hubAuth) Name() string {
	return "d2hub"
}
