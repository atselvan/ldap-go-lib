package ldap

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/ldap-go-lib/mocks"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
)

var (
	testOrganizationUnit1 = "test-ou-1"
	testOrganizationUnit2 = "test-ou-2"

	getOrganizationUnitsSearchResult = &ldap.SearchResult{
		Entries: []*ldap.Entry{
			getOrganizationUnitLDAPEntry(testOrganizationUnit1),
			getOrganizationUnitLDAPEntry(testOrganizationUnit2),
		},
	}
)

func TestOrganizationalUnitsManager_GetAll(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		oum := organizationalUnitsManager{Client: client}
		sr := oum.getSearchRequest()

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(getOrganizationUnitsSearchResult, nil)
		ldapMock.On(methodNameClose).Return(nil)

		organizationUnits, cErr := client.OrganizationalUnits.GetAll()
		assert.Nil(t, cErr)
		assert.Len(t, organizationUnits, 2)
		assert.Equal(t, testOrganizationUnit1, organizationUnits[0])
		assert.Equal(t, testOrganizationUnit2, organizationUnits[1])
	})

	t.Run("error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		oum := organizationalUnitsManager{Client: client}
		sr := oum.getSearchRequest()

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(nil, ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		organizationUnits, cErr := client.OrganizationalUnits.GetAll()
		assert.Empty(t, organizationUnits)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func getOrganizationUnitLDAPEntry(ou string) *ldap.Entry {
	attributes := []*ldap.EntryAttribute{
		{
			Name: OrganizationalUnitAttr,
			Values: []string{
				ou,
			},
		},
	}
	return &ldap.Entry{
		DN:         fmt.Sprintf("%s=%s,%s", OrganizationalUnitAttr, ou, testConfig.GroupBaseDN),
		Attributes: attributes,
	}
}
