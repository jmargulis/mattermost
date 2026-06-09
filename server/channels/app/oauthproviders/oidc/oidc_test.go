// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

// jmargulis: This file contains tests for the OIDC provider's user parsing and mapping logic.

package oauthoidc

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/shared/mlog"
	"github.com/mattermost/mattermost/server/public/shared/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCUserFromJSON(t *testing.T) {
	rctx := request.TestContext(t)
	provider := &OIDCProvider{}

	t.Run("valid user", func(t *testing.T) {
		u := OIDCUser{
			Sub:               "user-001",
			PreferredUsername: "alice",
			Email:             "alice@example.com",
			Name:              "Alice Admin",
			GivenName:         "Alice",
			FamilyName:        "Admin",
		}
		b, err := json.Marshal(u)
		require.NoError(t, err)

		got, err := provider.GetUserFromJSON(rctx, bytes.NewReader(b), nil, nil)
		require.NoError(t, err)
		require.NotNil(t, got.AuthData)
		assert.Equal(t, u.Sub, *got.AuthData)
	})

	t.Run("empty sub fails validation", func(t *testing.T) {
		_, err := provider.GetUserFromJSON(rctx, strings.NewReader(`{"email":"a@b.com"}`), nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sub")
	})

	t.Run("empty email fails validation", func(t *testing.T) {
		_, err := provider.GetUserFromJSON(rctx, strings.NewReader(`{"sub":"user-001"}`), nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email")
	})

	t.Run("invalid json", func(t *testing.T) {
		_, err := provider.GetUserFromJSON(rctx, strings.NewReader("not json"), nil, nil)
		require.Error(t, err)
	})
}

func TestOIDCUserIsValid(t *testing.T) {
	testCases := []struct {
		description string
		user        OIDCUser
		isValid     bool
		expectedErr string
	}{
		{"valid user", OIDCUser{Sub: "user-001", Email: "a@example.com"}, true, ""},
		{"empty sub", OIDCUser{Sub: "", Email: "a@example.com"}, false, "user sub claim must not be empty"},
		{"empty email", OIDCUser{Sub: "user-001", Email: ""}, false, "user email claim must not be empty"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			err := tc.user.IsValid()
			if tc.isValid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.expectedErr, err.Error())
			}
		})
	}
}

func TestUserFromOIDCUser(t *testing.T) {
	logger := mlog.CreateConsoleTestLogger(t)

	testCases := []struct {
		description       string
		oidcUser          OIDCUser
		expectedUsername  string
		expectedFirstName string
		expectedLastName  string
		expectedEmail     string
		expectedAuthData  string
		expectedRoles     string
	}{
		{
			// alice path: preferred_username + given_name/family_name + system_admin group
			description: "preferred_username, given+family names, system_admin group",
			oidcUser: OIDCUser{
				Sub:               "user-001",
				PreferredUsername: "alice",
				Email:             "alice@testorg.local",
				Name:              "Alice Admin",
				GivenName:         "Alice",
				FamilyName:        "Admin",
				Groups:            []string{"system_admin"},
			},
			expectedUsername:  "alice",
			expectedFirstName: "Alice",
			expectedLastName:  "Admin",
			expectedEmail:     "alice@testorg.local",
			expectedAuthData:  "user-001",
			expectedRoles:     model.SystemAdminRoleId + " " + model.SystemUserRoleId,
		},
		{
			// bob path: preferred_username present, name-splitting fallback (no given/family)
			description: "preferred_username, name-splitting fallback",
			oidcUser: OIDCUser{
				Sub:               "user-002",
				PreferredUsername: "bob",
				Email:             "bob@testorg.local",
				Name:              "Bob Builder",
			},
			expectedUsername:  "bob",
			expectedFirstName: "Bob",
			expectedLastName:  "Builder",
			expectedEmail:     "bob@testorg.local",
			expectedAuthData:  "user-002",
		},
		{
			// carol path: no preferred_username → email-prefix username
			description: "no preferred_username, email-prefix username fallback",
			oidcUser: OIDCUser{
				Sub:        "user-003",
				Email:      "carol@testorg.local",
				Name:       "Carol Cruz",
				GivenName:  "Carol",
				FamilyName: "Cruz",
			},
			expectedUsername:  "carol",
			expectedFirstName: "Carol",
			expectedLastName:  "Cruz",
			expectedEmail:     "carol@testorg.local",
			expectedAuthData:  "user-003",
		},
		{
			// no preferred_username and email has no @, falls back to sub
			description: "no preferred_username, no @ in email, sub username fallback",
			oidcUser: OIDCUser{
				Sub:   "user-004",
				Email: "noemail",
				Name:  "No At",
			},
			expectedUsername:  "user-004",
			expectedFirstName: "No",
			expectedLastName:  "At",
			expectedEmail:     "noemail",
			expectedAuthData:  "user-004",
		},
		{
			description: "name splitting: single name only",
			oidcUser: OIDCUser{
				Sub:               "user-005",
				PreferredUsername: "mononym",
				Email:             "mono@example.com",
				Name:              "Mononym",
			},
			expectedUsername:  "mononym",
			expectedFirstName: "Mononym",
			expectedLastName:  "",
			expectedEmail:     "mono@example.com",
			expectedAuthData:  "user-005",
		},
		{
			description: "name splitting: multiple last names",
			oidcUser: OIDCUser{
				Sub:               "user-006",
				PreferredUsername: "multi",
				Email:             "multi@example.com",
				Name:              "First Middle Van Der Lastname",
			},
			expectedUsername:  "multi",
			expectedFirstName: "First",
			expectedLastName:  "Middle Van Der Lastname",
			expectedEmail:     "multi@example.com",
			expectedAuthData:  "user-006",
		},
		{
			description: "given_name/family_name take priority over name splitting",
			oidcUser: OIDCUser{
				Sub:               "user-007",
				PreferredUsername: "priority",
				Email:             "priority@example.com",
				Name:              "Ignored Fullname",
				GivenName:         "Real",
				FamilyName:        "Name",
			},
			expectedUsername:  "priority",
			expectedFirstName: "Real",
			expectedLastName:  "Name",
			expectedEmail:     "priority@example.com",
			expectedAuthData:  "user-007",
		},
		{
			description: "only given_name, no family_name",
			oidcUser: OIDCUser{
				Sub:               "user-008",
				PreferredUsername: "givenonly",
				Email:             "given@example.com",
				Name:              "Given Only",
				GivenName:         "Given",
			},
			expectedUsername:  "givenonly",
			expectedFirstName: "Given",
			expectedLastName:  "",
			expectedEmail:     "given@example.com",
			expectedAuthData:  "user-008",
		},
		{
			description: "email is lowercased",
			oidcUser: OIDCUser{
				Sub:               "user-009",
				PreferredUsername: "upper",
				Email:             "UPPER@EXAMPLE.COM",
				Name:              "Upper User",
			},
			expectedUsername:  "upper",
			expectedFirstName: "Upper",
			expectedLastName:  "User",
			expectedEmail:     "upper@example.com",
			expectedAuthData:  "user-009",
		},
		{
			description: "username is cleaned (spaces become hyphens)",
			oidcUser: OIDCUser{
				Sub:               "user-010",
				PreferredUsername: "my test user",
				Email:             "clean@example.com",
				Name:              "Clean User",
			},
			expectedUsername:  "my-test-user",
			expectedFirstName: "Clean",
			expectedLastName:  "User",
			expectedEmail:     "clean@example.com",
			expectedAuthData:  "user-010",
		},
		{
			description: "system_admin not in groups, no role assignment",
			oidcUser: OIDCUser{
				Sub:               "user-011",
				PreferredUsername: "regularuser",
				Email:             "regular@example.com",
				Name:              "Regular User",
				Groups:            []string{"developers", "qa"},
			},
			expectedUsername:  "regularuser",
			expectedFirstName: "Regular",
			expectedLastName:  "User",
			expectedEmail:     "regular@example.com",
			expectedAuthData:  "user-011",
			expectedRoles:     "",
		},
		{
			description: "system_admin among multiple groups",
			oidcUser: OIDCUser{
				Sub:               "user-012",
				PreferredUsername: "adminuser",
				Email:             "admin@example.com",
				Name:              "Admin User",
				Groups:            []string{"developers", "system_admin", "qa"},
			},
			expectedUsername:  "adminuser",
			expectedFirstName: "Admin",
			expectedLastName:  "User",
			expectedEmail:     "admin@example.com",
			expectedAuthData:  "user-012",
			expectedRoles:     model.SystemAdminRoleId + " " + model.SystemUserRoleId,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			user := userFromOIDCUser(logger, &tc.oidcUser)

			require.NotNil(t, user)
			assert.Equal(t, tc.expectedUsername, user.Username)
			assert.Equal(t, tc.expectedFirstName, user.FirstName)
			assert.Equal(t, tc.expectedLastName, user.LastName)
			assert.Equal(t, tc.expectedEmail, user.Email)
			require.NotNil(t, user.AuthData)
			assert.Equal(t, tc.expectedAuthData, *user.AuthData)
			assert.Equal(t, model.UserAuthServiceOIDC, user.AuthService)
			if tc.expectedRoles != "" {
				assert.Equal(t, tc.expectedRoles, user.Roles)
			}
		})
	}
}

func TestOIDCProviderIsSameUser(t *testing.T) {
	provider := &OIDCProvider{}
	rctx := request.TestContext(t)

	sub1 := "user-001"
	sub2 := "user-002"

	testCases := []struct {
		description string
		dbUser      *model.User
		oauthUser   *model.User
		expected    bool
	}{
		{
			description: "same auth data",
			dbUser:      &model.User{AuthData: &sub1},
			oauthUser:   &model.User{AuthData: &sub1},
			expected:    true,
		},
		{
			description: "different auth data",
			dbUser:      &model.User{AuthData: &sub1},
			oauthUser:   &model.User{AuthData: &sub2},
			expected:    false,
		},
		{
			description: "nil dbUser auth data",
			dbUser:      &model.User{AuthData: nil},
			oauthUser:   &model.User{AuthData: &sub1},
			expected:    false,
		},
		{
			description: "nil oauthUser auth data",
			dbUser:      &model.User{AuthData: &sub1},
			oauthUser:   &model.User{AuthData: nil},
			expected:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			assert.Equal(t, tc.expected, provider.IsSameUser(rctx, tc.dbUser, tc.oauthUser))
		})
	}
}
