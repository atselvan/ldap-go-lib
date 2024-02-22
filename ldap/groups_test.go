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
	testCN       = "test-group"
	testGroupCn1 = "group1"
	testGroupCn2 = "group2"

	testUniqueMembers1 = []string{
		fmt.Sprintf("%s=%s,%s", userIdAttr, testUser1.Uid, testConfig.UserBaseDN),
		fmt.Sprintf("%s=%s,%s", userIdAttr, testUser2.Uid, testConfig.UserBaseDN),
		fmt.Sprintf("%s=%s,%s", noSuchUserGroupMemberCn, testUser1.Uid, testConfig.UserBaseDN),
	}

	testUniqueMembers2 = []string{
		fmt.Sprintf("%s=%s,%s", userIdAttr, testUser1.Uid, testConfig.UserBaseDN),
	}

	getGroupsOuEmptySearchResult = &ldap.SearchResult{
		Entries: []*ldap.Entry{
			getGroupLDAPEntry(testGroupCn1, testOrganizationUnit1, testUniqueMembers1),
			getGroupLDAPEntry(testGroupCn2, testOrganizationUnit1, testUniqueMembers1),
			getGroupLDAPEntry(testGroupCn1, testOrganizationUnit2, testUniqueMembers1),
			getGroupLDAPEntry(testGroupCn2, testOrganizationUnit2, testUniqueMembers1),
		},
	}

	getGroupsOuNotEmptySearchResult = &ldap.SearchResult{
		Entries: []*ldap.Entry{
			getGroupLDAPEntry(testGroupCn1, testOrganizationUnit1, testUniqueMembers1),
			getGroupLDAPEntry(testGroupCn2, testOrganizationUnit1, testUniqueMembers1),
		},
	}

	getGroupSearchResult1 = &ldap.SearchResult{
		Entries: []*ldap.Entry{
			getGroupLDAPEntry(testGroupCn1, testOrganizationUnit1, testUniqueMembers1),
		},
	}

	getGroupSearchResult2 = &ldap.SearchResult{
		Entries: []*ldap.Entry{
			getGroupLDAPEntry(testGroupCn1, testOrganizationUnit1, testUniqueMembers2),
		},
	}

	getFilteredGroupSearchResult = &ldap.SearchResult{
		Entries: []*ldap.Entry{
			getGroupLDAPEntry(testGroupCn1, testOrganizationUnit1, testUniqueMembers1),
			getGroupLDAPEntry(testGroupCn1, testOrganizationUnit2, testUniqueMembers2),
		},
	}
)

func TestGroupsManager_getDN(t *testing.T) {
	client := NewClient(testConfig)
	gm := groupsManager{Client: client}

	t.Run("cn and ou not empty", func(t *testing.T) {
		dn := gm.getDN(testCN, testOrganizationUnit1)
		assert.Equal(t, fmt.Sprintf("%s=%s,%s=%s,%s",
			CommonNameAttr,
			testCN,
			OrganizationalUnitAttr,
			testOrganizationUnit1,
			gm.Client.Config.GroupBaseDN,
		), dn)
	})

	t.Run("cn empty", func(t *testing.T) {
		dn := gm.getDN("", testOrganizationUnit1)
		assert.Equal(t, fmt.Sprintf("%s=%s,%s",
			OrganizationalUnitAttr,
			testOrganizationUnit1,
			gm.Client.Config.GroupBaseDN,
		), dn)
	})

	t.Run("cn and ou empty", func(t *testing.T) {
		dn := gm.getDN("", "")
		assert.Equal(t, gm.Client.Config.GroupBaseDN, dn)
	})

	t.Run("ou empty", func(t *testing.T) {
		dn := gm.getDN(testCN, "")
		assert.Equal(t, gm.Client.Config.GroupBaseDN, dn)
	})
}

func TestGroupsManager_GetAll(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).Return(nil)
		ldapMock.On(methodNameSearch, gm.getSearchRequest("", "", groupSearchFilter)).
			Return(getGroupsOuEmptySearchResult, nil)
		ldapMock.On(methodNameClose).Return(nil).Return(nil)

		groups, cErr := client.Groups.GetAll()
		assert.Nil(t, cErr)
		assert.NotNil(t, groups)
		assert.Len(t, groups, 4)
	})
}

func TestGroupsManager_Get(t *testing.T) {
	t.Run("get ou error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		oum := organizationalUnitsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(nil,
			ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		groups, cErr := client.Groups.Get("", testOrganizationUnit1)
		assert.Empty(t, groups)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})

	t.Run("invalid ou", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		oum := organizationalUnitsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
		ldapMock.On(methodNameClose).Return(nil)

		groups, cErr := client.Groups.Get("", "test")
		assert.Nil(t, groups)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, "Invalid organizational unit 'test'. Valid values are [test-ou-1 test-ou-2]",
			cErr.Message)
	})

	t.Run("success", func(t *testing.T) {
		t.Run("cn and ou empty", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest("", "", groupSearchFilter)).
				Return(getGroupsOuEmptySearchResult, nil)
			ldapMock.On(methodNameClose).Return(nil)

			groups, cErr := client.Groups.Get("", "")
			assert.Nil(t, cErr)
			assert.NotNil(t, groups)
			assert.Len(t, groups, 4)
		})

		t.Run("ou not empty", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			gm := groupsManager{Client: client}
			oum := organizationalUnitsManager{Client: client}

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest("", testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupsOuNotEmptySearchResult, nil)
			ldapMock.On(methodNameClose).Return(nil)

			groups, cErr := client.Groups.Get("", testOrganizationUnit1)
			assert.Nil(t, cErr)
			assert.NotNil(t, groups)
			assert.Len(t, groups, 2)
		})

		t.Run("cn and ou not empty", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			gm := groupsManager{Client: client}
			oum := organizationalUnitsManager{Client: client}

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupSearchResult1, nil)
			ldapMock.On(methodNameClose).Return(nil)

			groups, cErr := client.Groups.Get(testGroupCn1, testOrganizationUnit1)
			assert.Nil(t, cErr)
			assert.NotNil(t, groups)
			assert.Len(t, groups, 1)
		})
	})

	t.Run("user not found", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}
		oum := organizationalUnitsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).Return(nil)
		ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
		ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
			Return(nil, ldapNoSuchObjectErr)
		ldapMock.On(methodNameClose).Return(nil)

		groups, cErr := client.Groups.Get(testGroupCn1, testOrganizationUnit1)
		assert.Nil(t, groups)
		assert.Equal(t, errors.ErrCodeNotFound, cErr.Code)
		assert.Equal(t, http.StatusNotFound, cErr.Status)
		assert.Equal(t, fmt.Sprintf(groupNotFoundMsg, testGroupCn1, testOrganizationUnit1), cErr.Message)
	})

	t.Run("forbidden error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}
		oum := organizationalUnitsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).Return(nil)
		ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
		ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
			Return(nil, ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		groups, cErr := client.Groups.Get(testGroupCn1, testOrganizationUnit1)
		assert.Nil(t, groups)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestGroupsManager_GetFilter(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}
		searchFilter := fmt.Sprintf(WildcardGroupsSearchFilter, testGroupCn1)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).Return(nil)
		ldapMock.On(methodNameSearch, gm.getSearchRequest("", "", searchFilter)).
			Return(getFilteredGroupSearchResult, nil)
		ldapMock.On(methodNameClose).Return(nil)

		groups, cErr := client.Groups.GetFilter(searchFilter)
		assert.Nil(t, cErr)
		assert.NotNil(t, groups)
		assert.Len(t, groups, 2)
		assert.Equal(t, testGroupCn1, groups[0].Cn)
		assert.Equal(t, testGroupCn1, groups[1].Cn)
	})

	t.Run("error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}
		searchFilter := fmt.Sprintf(WildcardGroupsSearchFilter, testGroupCn1)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).Return(nil)
		ldapMock.On(methodNameSearch, gm.getSearchRequest("", "", searchFilter)).
			Return(nil, ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		groups, cErr := client.Groups.GetFilter(searchFilter)
		assert.Nil(t, groups)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestGroupsManager_Create(t *testing.T) {

	t.Run("validate", func(t *testing.T) {
		t.Run("empty params", func(t *testing.T) {
			client := NewClient(testConfig)
			cErr := client.Groups.Create("", "", []string{})
			assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
			assert.Equal(t, http.StatusBadRequest, cErr.Status)
			assert.Equal(t, fmt.Sprintf(
				errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter],
				[]string{
					CommonNameAttr,
					OrganizationalUnitAttr,
				},
			), cErr.Message)
		})

		t.Run("invalid ou", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameClose).Return(nil)

			cErr := client.Groups.Create(testGroupCn1, "test", []string{})
			assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
			assert.Equal(t, http.StatusBadRequest, cErr.Status)
			assert.Equal(t, "Invalid organizational unit 'test'. Valid values are [test-ou-1 test-ou-2]",
				cErr.Message)
		})
	})

	t.Run("success", func(t *testing.T) {
		t.Run("with members", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			gm := groupsManager{Client: client}
			oum := organizationalUnitsManager{Client: client}

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameAdd, gm.getAddRequest(testGroupCn1, testOrganizationUnit1,
				[]string{testUser1.Uid, testUser2.Uid})).Return(nil)
			ldapMock.On(methodNameClose).Return(nil)

			cErr := client.Groups.Create(testGroupCn1, testOrganizationUnit1, []string{testUser1.Uid, testUser2.Uid})
			assert.Nil(t, cErr)
		})

		t.Run("without members", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			gm := groupsManager{Client: client}
			oum := organizationalUnitsManager{Client: client}

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameAdd, gm.getAddRequest(testGroupCn1, testOrganizationUnit1,
				[]string{noSuchUserGroupMemberCn})).Return(nil)
			ldapMock.On(methodNameClose).Return(nil)

			cErr := client.Groups.Create(testGroupCn1, testOrganizationUnit1, []string{})
			assert.Nil(t, cErr)
		})
	})

	t.Run("group already exists", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}
		oum := organizationalUnitsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
		ldapMock.On(methodNameAdd, gm.getAddRequest(testGroupCn1, testOrganizationUnit1,
			[]string{testUser1.Uid, testUser2.Uid})).Return(ldapEntryAlreadyExistsErr)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Groups.Create(testGroupCn1, testOrganizationUnit1, []string{testUser1.Uid, testUser2.Uid})
		assert.Equal(t, errors.ErrCodeConflict, cErr.Code)
		assert.Equal(t, http.StatusConflict, cErr.Status)
		assert.Equal(t, fmt.Sprintf(groupAlreadyExistsMsg, testGroupCn1, testOrganizationUnit1), cErr.Message)
	})

	t.Run("forbidden error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}
		oum := organizationalUnitsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
		ldapMock.On(methodNameAdd, gm.getAddRequest(testGroupCn1, testOrganizationUnit1,
			[]string{testUser1.Uid, testUser2.Uid})).Return(ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Groups.Create(testGroupCn1, testOrganizationUnit1, []string{testUser1.Uid, testUser2.Uid})
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestGroupsManager_Delete(t *testing.T) {

	t.Run("validate", func(t *testing.T) {
		t.Run("empty params", func(t *testing.T) {
			client := NewClient(testConfig)
			cErr := client.Groups.Delete("", "")
			assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
			assert.Equal(t, http.StatusBadRequest, cErr.Status)
			assert.Equal(t, fmt.Sprintf(
				errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter],
				[]string{
					CommonNameAttr,
					OrganizationalUnitAttr,
				},
			), cErr.Message)
		})

		t.Run("invalid ou", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameClose).Return(nil)

			cErr := client.Groups.Delete(testGroupCn1, "test")
			assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
			assert.Equal(t, http.StatusBadRequest, cErr.Status)
			assert.Equal(t, "Invalid organizational unit 'test'. Valid values are [test-ou-1 test-ou-2]",
				cErr.Message)
		})
	})

	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}
		oum := organizationalUnitsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
		ldapMock.On(methodNameDelete, gm.getDeleteRequest(testGroupCn1, testOrganizationUnit1)).
			Return(nil)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Groups.Delete(testGroupCn1, testOrganizationUnit1)
		assert.Nil(t, cErr)
	})

	t.Run("group not found error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}
		oum := organizationalUnitsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
		ldapMock.On(methodNameDelete, gm.getDeleteRequest(testGroupCn1, testOrganizationUnit1)).
			Return(ldapNoSuchObjectErr)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Groups.Delete(testGroupCn1, testOrganizationUnit1)
		assert.Equal(t, errors.ErrCodeNotFound, cErr.Code)
		assert.Equal(t, http.StatusNotFound, cErr.Status)
		assert.Equal(t, fmt.Sprintf(groupNotFoundMsg, testGroupCn1, testOrganizationUnit1), cErr.Message)
	})

	t.Run("forbidden error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		gm := groupsManager{Client: client}
		oum := organizationalUnitsManager{Client: client}

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
		ldapMock.On(methodNameDelete, gm.getDeleteRequest(testGroupCn1, testOrganizationUnit1)).
			Return(ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Groups.Delete(testGroupCn1, testOrganizationUnit1)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestGroupsManager_AddMembers(t *testing.T) {
	t.Run("validation error", func(t *testing.T) {
		client := NewClient(testConfig)
		cErr := client.Groups.AddMembers("", "", []string{})
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(
			errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter],
			[]string{
				CommonNameAttr,
				OrganizationalUnitAttr,
			},
		), cErr.Message)
	})

	t.Run("success", func(t *testing.T) {
		t.Run("with new member", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupSearchResult1, nil)
			mr := gm.getModifyRequest(testGroupCn1, testOrganizationUnit1)
			mr.Add(uniqueMemberAttr, []string{gm.getUniqueMemberDn(testUser3.Uid)})
			mr.Delete(uniqueMemberAttr, []string{gm.getUniqueMemberDn(noSuchUserGroupMemberCn)})
			ldapMock.On(methodNameModify, mr).Return(nil)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.AddMembers(testGroupCn1, testOrganizationUnit1, []string{testUser3.Uid})
			assert.Nil(t, cErr)
		})

		t.Run("with existing member", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupSearchResult1, nil)
			mr := gm.getModifyRequest(testGroupCn1, testOrganizationUnit1)
			mr.Delete(uniqueMemberAttr, []string{gm.getUniqueMemberDn(noSuchUserGroupMemberCn)})
			ldapMock.On(methodNameModify, mr).Return(nil)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.AddMembers(testGroupCn1, testOrganizationUnit1, []string{testUser1.Uid})
			assert.Nil(t, cErr)
		})

		t.Run("with no member", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupSearchResult1, nil)
			mr := gm.getModifyRequest(testGroupCn1, testOrganizationUnit1)
			mr.Delete(uniqueMemberAttr, []string{gm.getUniqueMemberDn(noSuchUserGroupMemberCn)})
			ldapMock.On(methodNameModify, mr).Return(nil)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.AddMembers(testGroupCn1, testOrganizationUnit1, []string{})
			assert.Nil(t, cErr)
		})

		t.Run("get ou error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).
				Return(nil, ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.AddMembers(testGroupCn1, testOrganizationUnit1, []string{})
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})

		t.Run("get group error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(nil, ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.AddMembers(testGroupCn1, testOrganizationUnit1, []string{})
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})

		t.Run("ldap modify error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupSearchResult1, nil)
			mr := gm.getModifyRequest(testGroupCn1, testOrganizationUnit1)
			mr.Delete(uniqueMemberAttr, []string{gm.getUniqueMemberDn(noSuchUserGroupMemberCn)})
			ldapMock.On(methodNameModify, mr).Return(ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.AddMembers(testGroupCn1, testOrganizationUnit1, []string{})
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})
	})
}

func TestGroupsManager_RemoveMembers(t *testing.T) {
	t.Run("validation error", func(t *testing.T) {
		client := NewClient(testConfig)
		cErr := client.Groups.RemoveMembers("", "", []string{})
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(
			errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter],
			[]string{
				CommonNameAttr,
				OrganizationalUnitAttr,
			},
		), cErr.Message)
	})

	t.Run("success", func(t *testing.T) {
		t.Run("with existing member", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupSearchResult1, nil)
			mr := gm.getModifyRequest(testGroupCn1, testOrganizationUnit1)
			mr.Delete(uniqueMemberAttr, []string{gm.getUniqueMemberDn(testUser1.Uid)})
			ldapMock.On(methodNameModify, mr).Return(nil)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.RemoveMembers(testGroupCn1, testOrganizationUnit1, []string{testUser1.Uid})
			assert.Nil(t, cErr)
		})

		t.Run("with non existing member", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupSearchResult1, nil)
			mr := gm.getModifyRequest(testGroupCn1, testOrganizationUnit1)
			ldapMock.On(methodNameModify, mr).Return(nil)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.RemoveMembers(testGroupCn1, testOrganizationUnit1, []string{testUser3.Uid})
			assert.Nil(t, cErr)
		})

		t.Run("with all member(s)", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupSearchResult2, nil)
			mr := gm.getModifyRequest(testGroupCn1, testOrganizationUnit1)
			mr.Delete(uniqueMemberAttr, []string{gm.getUniqueMemberDn(testUser1.Uid)})
			mr.Add(uniqueMemberAttr, []string{gm.getUniqueMemberDn(noSuchUserGroupMemberCn)})
			ldapMock.On(methodNameModify, mr).Return(nil)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.RemoveMembers(testGroupCn1, testOrganizationUnit1, []string{testUser1.Uid})
			assert.Nil(t, cErr)
		})

		t.Run("get ou error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).
				Return(nil, ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.RemoveMembers(testGroupCn1, testOrganizationUnit1, []string{})
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})

		t.Run("get group error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(nil, ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.RemoveMembers(testGroupCn1, testOrganizationUnit1, []string{})
			assert.NotNil(t, cErr)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})

		t.Run("ldap modify error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

			oum := organizationalUnitsManager{Client: client}
			gm := groupsManager{Client: client}

			ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(nil)
			ldapMock.On(methodNameSearch, oum.getSearchRequest()).Return(getOrganizationUnitsSearchResult, nil)
			ldapMock.On(methodNameSearch, gm.getSearchRequest(testGroupCn1, testOrganizationUnit1, groupSearchFilter)).
				Return(getGroupSearchResult1, nil)
			mr := gm.getModifyRequest(testGroupCn1, testOrganizationUnit1)
			ldapMock.On(methodNameModify, mr).Return(ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil).Return(nil)

			cErr := client.Groups.RemoveMembers(testGroupCn1, testOrganizationUnit1, []string{})
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})
	})
}

func getGroupLDAPEntry(cn, ou string, uniqueMembers []string) *ldap.Entry {
	attributes := []*ldap.EntryAttribute{
		{
			Name: CommonNameAttr,
			Values: []string{
				cn,
			},
		},
		{
			Name:   uniqueMemberAttr,
			Values: uniqueMembers,
		},
	}
	return &ldap.Entry{
		DN: fmt.Sprintf("%s=%s,%s=%s,%s",
			CommonNameAttr,
			cn,
			OrganizationalUnitAttr,
			ou,
			testConfig.GroupBaseDN,
		),
		Attributes: attributes,
	}
}
