package internal

import (
	"fmt"
	"time"
)

var MaxIssueDelay = time.Minute * 10

func (a *AuthnRequest) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("request not contain the id\n")
	}
	if a.IssueInstant.Add(MaxIssueDelay).Before(time.Now()) {
		return fmt.Errorf("request expired at %s\n", a.IssueInstant.Add(MaxIssueDelay))
	}
	if a.Version != "2.0" {
		return fmt.Errorf("expected SAML request version 2.0 got %v\n", a.Version)
	}
	return nil
}
