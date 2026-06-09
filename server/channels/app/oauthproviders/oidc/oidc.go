// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// jmargulis: This file implements the OIDC provider for app layer OAuth, which allows Mattermost
// to integrate with any OIDC-compliant identity provider. The provider's main responsibility is
// parsing the user info returned by the IdP and mapping it to a Mattermost user, including handling
// various fallback paths for missing claims and mapping OIDC groups to Mattermost roles.

package oauthoidc

import (
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/mattermost/mattermost/server/v8/einterfaces"
)

type OIDCProvider struct {
}

type OIDCUser struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	Groups            []string `json:"groups"`
}

func init() {
	provider := &OIDCProvider{}
	einterfaces.RegisterOAuthProvider(model.UserAuthServiceOIDC, provider)
	// Also register as "openid" so the webapp's built-in OpenID button triggers this provider.
	einterfaces.RegisterOAuthProvider(model.ServiceOpenid, provider)
}

func userFromOIDCUser(logger mlog.LoggerIFace, u *OIDCUser) *model.User {
	user := &model.User{}

	username := u.PreferredUsername
	if username == "" {
		// Fall back to email prefix
		if at := strings.Index(u.Email, "@"); at > 0 {
			username = u.Email[:at]
		} else {
			username = u.Sub
		}
	}
	user.Username = model.CleanUsername(logger, username)

	if u.GivenName != "" || u.FamilyName != "" {
		user.FirstName = u.GivenName
		user.LastName = u.FamilyName
	} else {
		parts := strings.SplitN(u.Name, " ", 2)
		if len(parts) == 2 {
			user.FirstName = parts[0]
			user.LastName = parts[1]
		} else {
			user.FirstName = u.Name
		}
	}

	user.Email = strings.ToLower(u.Email)
	sub := u.Sub
	user.AuthData = &sub
	user.AuthService = model.UserAuthServiceOIDC

	for _, g := range u.Groups {
		if g == "system_admin" {
			user.Roles = model.SystemAdminRoleId + " " + model.SystemUserRoleId
			break
		}
	}

	return user
}

func oidcUserFromJSON(data io.Reader) (*OIDCUser, error) {
	decoder := json.NewDecoder(data)
	var u OIDCUser
	if err := decoder.Decode(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (u *OIDCUser) IsValid() error {
	if u.Sub == "" {
		return errors.New("user sub claim must not be empty")
	}
	if u.Email == "" {
		return errors.New("user email claim must not be empty")
	}
	return nil
}

func (gp *OIDCProvider) GetUserFromJSON(c request.CTX, data io.Reader, tokenUser *model.User, _ *model.SSOSettings) (*model.User, error) {
	u, err := oidcUserFromJSON(data)
	if err != nil {
		return nil, err
	}
	if err = u.IsValid(); err != nil {
		return nil, err
	}
	return userFromOIDCUser(c.Logger(), u), nil
}

func (gp *OIDCProvider) GetSSOSettings(_ request.CTX, config *model.Config, _ string) (*model.SSOSettings, error) {
	return &config.OIDCSettings, nil
}

func (gp *OIDCProvider) GetUserFromIdToken(_ request.CTX, idToken string) (*model.User, error) {
	return nil, nil
}

func (gp *OIDCProvider) IsSameUser(_ request.CTX, dbUser, oauthUser *model.User) bool {
	if dbUser.AuthData == nil || oauthUser.AuthData == nil {
		return false
	}
	return *dbUser.AuthData == *oauthUser.AuthData
}
