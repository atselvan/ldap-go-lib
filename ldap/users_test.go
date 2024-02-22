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
	// Test User 1
	testUser1 = User{
		Uid:            "C00001",
		AltUid:         "john.doe",
		Cn:             "John",
		Sn:             "Doe",
		DisplayName:    "John Doe",
		EmployeeNumber: "E100001",
		Mail:           "john.doe@company.com",
		Status:         UserStatusActive,
		UserPassword:   "somePassword",
	}

	// Test User 2
	testUser2 = User{
		Uid:            "C00002",
		AltUid:         "jane.doe",
		Cn:             "Jane",
		Sn:             "Doe",
		DisplayName:    "Jane Doe",
		EmployeeNumber: "E100002",
		Mail:           "jane.doe@company.com",
		Status:         UserStatusDeleted,
	}

	// Test User 3
	testUser3 = User{
		Uid:            "ABC_BUILDER",
		AltUid:         "ABC_BUILDER",
		Cn:             "ABC",
		Sn:             "Technical User",
		DisplayName:    "ABC Technical User",
		EmployeeNumber: "",
		Mail:           "abc@company.com",
		Status:         UserStatusActive,
	}

	// Test User 4
	testUser4 = User{
		Uid:            "nxrm-ado-agent",
		AltUid:         "nxrm-ado-agent",
		Cn:             "NXRM - ADO",
		Sn:             "Technical User",
		DisplayName:    "NXRM - ADO Technical User",
		EmployeeNumber: "",
		Mail:           "abc@company.com",
		Status:         UserStatusActive,
	}

	getUsersSearchResult = ldap.SearchResult{
		Entries: []*ldap.Entry{
			getUserLDAPEntry(testUser1),
			getUserLDAPEntry(testUser2),
			getUserLDAPEntry(testUser3),
			getUserLDAPEntry(testUser4),
		},
	}

	getUsersEmptySearchResult = &ldap.SearchResult{
		Entries: []*ldap.Entry{},
	}

	getUserSearchResult = &ldap.SearchResult{
		Entries: []*ldap.Entry{
			getUserLDAPEntry(testUser1),
		},
	}

	getBuilderAccountFilteredSearchResult = &ldap.SearchResult{
		Entries: []*ldap.Entry{
			getUserLDAPEntry(testUser3),
		},
	}

	passwordModifySearchResult = &ldap.PasswordModifyResult{
		GeneratedPassword: testUser1.UserPassword,
	}
)

func TestUsersManager_GetAll(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		um := usersManager{Client: client}
		sr := um.getUsersSearchRequest(userSearchFilter)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(&getUsersSearchResult, nil)
		ldapMock.On(methodNameClose).Return(nil)

		users, cErr := client.Users.GetAll()
		assert.Nil(t, cErr)
		assert.Len(t, users, 4)
		assert.Equal(t, testUser1.Uid, users[0].Uid)
		assert.Equal(t, testUser2.Uid, users[1].Uid)
		assert.Equal(t, testUser3.Uid, users[2].Uid)
		assert.Equal(t, testUser4.Uid, users[3].Uid)
	})

	t.Run("success: empty list", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		um := usersManager{Client: client}
		sr := um.getUsersSearchRequest(userSearchFilter)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(getUsersEmptySearchResult, nil)
		ldapMock.On(methodNameClose).Return(nil)

		users, cErr := client.Users.GetAll()
		assert.Nil(t, cErr)
		assert.Len(t, users, 0)
	})

	t.Run("error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		sr := um.getUsersSearchRequest(userSearchFilter)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(nil, ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		users, cErr := client.Users.GetAll()
		assert.Nil(t, users)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestUsersManager_Get(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		um := usersManager{Client: client}
		sr := um.getUserSearchRequest(um.getDN(testUser1.Uid))

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(getUserSearchResult, nil)
		ldapMock.On(methodNameClose).Return(nil)

		user, cErr := client.Users.Get(testUser1.Uid)
		assert.Nil(t, cErr)
		assert.Equal(t, testUser1.Uid, user.Uid)
		assert.Equal(t, testUser1.AltUid, user.AltUid)
		assert.Equal(t, testUser1.Cn, user.Cn)
		assert.Equal(t, testUser1.Sn, user.Sn)
		assert.Equal(t, testUser1.DisplayName, user.DisplayName)
		assert.Equal(t, testUser1.EmployeeNumber, user.EmployeeNumber)
		assert.Equal(t, testUser1.Mail, user.Mail)
		assert.Equal(t, testUser1.Status, user.Status)
	})

	t.Run("validate uid", func(t *testing.T) {
		client := NewClient(testConfig)

		user, cErr := client.Users.Get("")
		assert.Nil(t, user)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(
			errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter],
			[]string{
				userIdAttr,
			},
		), cErr.Message)
	})

	t.Run("user not found", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		sr := um.getUserSearchRequest(um.getDN(testUser1.Uid))

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(nil, ldapNoSuchObjectErr)
		ldapMock.On(methodNameClose).Return(nil)

		user, cErr := client.Users.Get(testUser1.Uid)
		assert.Nil(t, user)
		assert.Equal(t, errors.ErrCodeNotFound, cErr.Code)
		assert.Equal(t, http.StatusNotFound, cErr.Status)
		assert.Equal(t, fmt.Sprintf(userNotFoundMsg, testUser1.Uid), cErr.Message)
	})

	t.Run("error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		sr := um.getUserSearchRequest(um.getDN(testUser1.Uid))

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(nil, ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		user, cErr := client.Users.Get(testUser1.Uid)
		assert.Nil(t, user)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestUsersManager_Filter(t *testing.T) {
	t.Run("empty key", func(t *testing.T) {
		client := NewClient(testConfig)
		users, cErr := client.Users.Filter("", testUser1.Uid)
		assert.Nil(t, users)
		assert.NotNil(t, cErr)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(
			errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter],
			[]string{
				"key",
			},
		), cErr.Message)
	})

	t.Run("empty value", func(t *testing.T) {
		client := NewClient(testConfig)
		users, cErr := client.Users.Filter(userIdAttr, "")
		assert.Nil(t, users)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(
			errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter],
			[]string{
				"value",
			},
		), cErr.Message)
	})

	t.Run("invalid key", func(t *testing.T) {
		client := NewClient(testConfig)
		users, cErr := client.Users.Filter(testUser1.Uid, testUser1.Uid)
		assert.Nil(t, users)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(invalidFilterKeyErrMsg, testUser1.Uid, userAttributes), cErr.Message)
	})

	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		userSearchFilter := fmt.Sprintf(WildcardUserSearchFilter, userIdAttr, BuilderAccountTypeFilter)
		sr := um.getUsersSearchRequest(userSearchFilter)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(getBuilderAccountFilteredSearchResult, nil)
		ldapMock.On(methodNameClose).Return(nil)

		users, cErr := client.Users.Filter(userIdAttr, BuilderAccountTypeFilter)
		assert.Nil(t, cErr)
		assert.Len(t, users, 1)
		assert.Equal(t, testUser3.Uid, users[0].Uid)
	})

	t.Run("error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		userSearchFilter := fmt.Sprintf(WildcardUserSearchFilter, userIdAttr, BuilderAccountTypeFilter)
		sr := um.getUsersSearchRequest(userSearchFilter)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(nil, ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		users, cErr := client.Users.Filter(userIdAttr, BuilderAccountTypeFilter)
		assert.Nil(t, users)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestUsersManager_FilterByStatus(t *testing.T) {
	t.Run("empty status", func(t *testing.T) {
		client := NewClient(testConfig)
		users, cErr := client.Users.FilterByStatus("")
		assert.Nil(t, users)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(invalidStatusErrMsg, "", validStatusList), cErr.Message)
	})

	t.Run("invalid status", func(t *testing.T) {
		client := NewClient(testConfig)
		users, cErr := client.Users.FilterByStatus("invalid")
		assert.Nil(t, users)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(invalidStatusErrMsg, "invalid", validStatusList), cErr.Message)
	})

	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		userSearchFilter := fmt.Sprintf(WildcardUserSearchFilter, statusAttr, UserStatusActive)
		sr := um.getUsersSearchRequest(userSearchFilter)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(getUserSearchResult, nil)
		ldapMock.On(methodNameClose).Return(nil)

		users, cErr := client.Users.FilterByStatus(UserStatusActive)
		assert.Nil(t, cErr)
		assert.Len(t, users, 1)
		assert.Equal(t, testUser1.Uid, users[0].Uid)
	})

	t.Run("error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		userSearchFilter := fmt.Sprintf(WildcardUserSearchFilter, statusAttr, UserStatusActive)
		sr := um.getUsersSearchRequest(userSearchFilter)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameSearch, sr).Return(nil, ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		users, cErr := client.Users.FilterByStatus(UserStatusActive)
		assert.Nil(t, users)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestUsersManager_FilterByType(t *testing.T) {
	t.Run("empty type", func(t *testing.T) {
		client := NewClient(testConfig)
		users, cErr := client.Users.FilterByType("")
		assert.Nil(t, users)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(invalidUserTypeErrMsg, "", validUserTypes), cErr.Message)
	})

	t.Run("invalid status", func(t *testing.T) {
		client := NewClient(testConfig)
		users, cErr := client.Users.FilterByType("invalid")
		assert.Nil(t, users)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(invalidUserTypeErrMsg, "invalid", validUserTypes), cErr.Message)
	})

	t.Run("personal accounts", func(t *testing.T) {

		t.Run("success", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			sr := um.getUsersSearchRequest(userSearchFilter)

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, sr).Return(&getUsersSearchResult, nil)
			ldapMock.On(methodNameClose).Return(nil)

			users, cErr := client.Users.FilterByType(UserTypePersonal)
			assert.Nil(t, cErr)
			assert.Len(t, users, 2)
			assert.Equal(t, testUser1.Uid, users[0].Uid)
			assert.Equal(t, testUser2.Uid, users[1].Uid)
		})

		t.Run("regex compile error", func(t *testing.T) {
			ogRegex := PersonalUserTypeRegex
			PersonalUserTypeRegex = "[A-z{1}"
			client := NewClient(testConfig)

			users, cErr := client.Users.FilterByType(UserTypePersonal)
			assert.Nil(t, users)
			assert.Equal(t, errors.ErrCodeInternalServerError, cErr.Code)
			assert.Equal(t, http.StatusInternalServerError, cErr.Status)
			assert.Contains(t, cErr.Message, "error parsing regexp")

			PersonalUserTypeRegex = ogRegex
		})

		t.Run("get users error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			sr := um.getUsersSearchRequest(userSearchFilter)

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, sr).Return(nil, ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil)

			users, cErr := client.Users.FilterByType(UserTypePersonal)
			assert.Nil(t, users)
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})
	})

	t.Run("builder accounts", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			userSearchFilter := fmt.Sprintf(WildcardUserSearchFilter, userIdAttr, BuilderAccountTypeFilter)
			sr := um.getUsersSearchRequest(userSearchFilter)

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, sr).Return(getBuilderAccountFilteredSearchResult, nil)
			ldapMock.On(methodNameClose).Return(nil)

			users, cErr := client.Users.FilterByType(UserTypeBuilder)
			assert.Nil(t, cErr)
			assert.Len(t, users, 1)
			assert.Equal(t, testUser3.Uid, users[0].Uid)
		})

		t.Run("error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			userSearchFilter := fmt.Sprintf(WildcardUserSearchFilter, userIdAttr, BuilderAccountTypeFilter)
			sr := um.getUsersSearchRequest(userSearchFilter)

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, sr).Return(nil, ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil)

			users, cErr := client.Users.FilterByType(UserTypeBuilder)
			assert.Nil(t, users)
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})
	})

	t.Run("npa accounts", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			sr := um.getUsersSearchRequest(userSearchFilter)

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, sr).Return(&getUsersSearchResult, nil)
			ldapMock.On(methodNameClose).Return(nil)

			users, cErr := client.Users.FilterByType(UserTypeNPA)
			assert.Nil(t, cErr)
			assert.Len(t, users, 1)
			assert.Equal(t, testUser4.Uid, users[0].Uid)
		})

		t.Run("regex compile error", func(t *testing.T) {
			ogRegex := PersonalUserTypeRegex
			PersonalUserTypeRegex = "[A-z{1}"
			client := NewClient(testConfig)

			users, cErr := client.Users.FilterByType(UserTypeNPA)
			assert.Nil(t, users)
			assert.Equal(t, errors.ErrCodeInternalServerError, cErr.Code)
			assert.Equal(t, http.StatusInternalServerError, cErr.Status)
			assert.Contains(t, cErr.Message, "error parsing regexp")

			PersonalUserTypeRegex = ogRegex
		})

		t.Run("get users error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			sr := um.getUsersSearchRequest(userSearchFilter)

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On(methodNameSearch, sr).Return(nil, ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil)

			users, cErr := client.Users.FilterByType(UserTypeNPA)
			assert.Nil(t, users)
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})
	})
}

func TestUsersManager_Create(t *testing.T) {
	t.Run("validate user", func(t *testing.T) {
		client := NewClient(testConfig)
		user := User{}

		cErr := client.Users.Create(user)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(
			errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter],
			[]string{
				userIdAttr,
				alternateUserIdAttr,
				CommonNameAttr,
				familyNameAttr,
				displayNameAttr,
				mailAttr,
				userPasswordAttr,
				statusAttr,
			},
		), cErr.Message)
	})

	t.Run("invalid status", func(t *testing.T) {
		client := NewClient(testConfig)
		user := testUser1
		user.Status = "invalid"

		cErr := client.Users.Create(user)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(invalidStatusErrMsg, "invalid", validStatusList), cErr.Message)
	})

	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		ar := um.getAddRequest(testUser1)
		pmr := um.getPasswordModifyRequest(testUser1.Uid, testUser1.UserPassword, testUser1.UserPassword)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameAdd, ar).Return(nil)
		ldapMock.On("PasswordModify", pmr).Return(nil, nil)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Users.Create(testUser1)
		assert.Nil(t, cErr)
	})

	t.Run("user already exists error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		ar := um.getAddRequest(testUser1)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameAdd, ar).Return(ldapEntryAlreadyExistsErr)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Users.Create(testUser1)
		assert.Equal(t, errors.ErrCodeConflict, cErr.Code)
		assert.Equal(t, http.StatusConflict, cErr.Status)
		assert.Equal(t, fmt.Sprintf(userAlreadyExistsMsg, testUser1.Uid), cErr.Message)
	})

	t.Run("forbidden error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		ar := um.getAddRequest(testUser1)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameAdd, ar).Return(ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Users.Create(testUser1)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})

	t.Run("password modify error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		ar := um.getAddRequest(testUser1)
		pmr := um.getPasswordModifyRequest(testUser1.Uid, testUser1.UserPassword, testUser1.UserPassword)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameAdd, ar).Return(nil)
		ldapMock.On("PasswordModify", pmr).Return(nil, ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Users.Create(testUser1)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestUsersManager_Delete(t *testing.T) {
	t.Run("validate uid", func(t *testing.T) {
		client := NewClient(testConfig)

		cErr := client.Users.Delete("")
		assert.NotNil(t, cErr)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(
			errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter],
			[]string{
				userIdAttr,
			},
		), cErr.Message)
	})

	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		dr := um.getDeleteRequest(testUser1.Uid)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameDelete, dr).Return(nil)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Users.Delete(testUser1.Uid)
		assert.Nil(t, cErr)
	})

	t.Run("user does not exist", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		dr := um.getDeleteRequest(testUser1.Uid)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameDelete, dr).Return(ldapNoSuchObjectErr)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Users.Delete(testUser1.Uid)
		assert.Equal(t, errors.ErrCodeNotFound, cErr.Code)
		assert.Equal(t, http.StatusNotFound, cErr.Status)
		assert.Equal(t, fmt.Sprintf(userNotFoundMsg, testUser1.Uid), cErr.Message)
	})

	t.Run("forbidden error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
		um := usersManager{Client: client}
		dr := um.getDeleteRequest(testUser1.Uid)

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)
		ldapMock.On(methodNameDelete, dr).Return(ldapInsufficientRightsErr)
		ldapMock.On(methodNameClose).Return(nil)

		cErr := client.Users.Delete(testUser1.Uid)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})
}

func TestUsersManager_Authenticate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
			Return(nil)

		cErr := client.Users.Authenticate()
		assert.Nil(t, cErr)
	})
}

func TestUsersManager_SetNewPassword(t *testing.T) {
	t.Run("new generated password", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			pmr := um.getPasswordModifyRequest(testUser1.Uid, "", "")

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On("PasswordModify", pmr).Return(passwordModifySearchResult, nil)
			ldapMock.On(methodNameClose).Return(nil)

			result, cErr := client.Users.SetNewPassword(testUser1.Uid, "")
			assert.Nil(t, cErr)
			assert.Equal(t, testUser1.UserPassword, result)
		})

		t.Run("error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			pmr := um.getPasswordModifyRequest(testUser1.Uid, "", "")

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On("PasswordModify", pmr).Return(nil, ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil)

			result, cErr := client.Users.SetNewPassword(testUser1.Uid, "")
			assert.Empty(t, result)
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})

		t.Run("user not found", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			pmr := um.getPasswordModifyRequest(testUser1.Uid, "", "")

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On("PasswordModify", pmr).Return(nil, ldapNoSuchObjectErr)
			ldapMock.On(methodNameClose).Return(nil)

			result, cErr := client.Users.SetNewPassword(testUser1.Uid, "")
			assert.Empty(t, result)
			assert.Equal(t, errors.ErrCodeNotFound, cErr.Code)
			assert.Equal(t, http.StatusNotFound, cErr.Status)
			assert.Equal(t, fmt.Sprintf(userNotFoundMsg, testUser1.Uid), cErr.Message)
		})
	})

	t.Run("new custom password", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			pmr := um.getPasswordModifyRequest(testUser1.Uid, "", testUser1.UserPassword)

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On("PasswordModify", pmr).Return(passwordModifySearchResult, nil)
			ldapMock.On(methodNameClose).Return(nil)

			result, cErr := client.Users.SetNewPassword(testUser1.Uid, testUser1.UserPassword)
			assert.Nil(t, cErr)
			assert.Equal(t, testUser1.UserPassword, result)
		})

		t.Run("error", func(t *testing.T) {
			ldapMock := mocks.NewClient(t)
			client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())
			um := usersManager{Client: client}
			pmr := um.getPasswordModifyRequest(testUser1.Uid, "", testUser1.UserPassword)

			ldapMock.On(methodNameBind, client.Config.BindUser, client.Config.BindPassword).
				Return(nil)
			ldapMock.On("PasswordModify", pmr).Return(nil, ldapInsufficientRightsErr)
			ldapMock.On(methodNameClose).Return(nil)

			result, cErr := client.Users.SetNewPassword(testUser1.Uid, testUser1.UserPassword)
			assert.Empty(t, result)
			assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
			assert.Equal(t, http.StatusForbidden, cErr.Status)
			assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
		})
	})
}

func getUserLDAPEntry(user User) *ldap.Entry {
	attributes := []*ldap.EntryAttribute{
		{
			Name: userIdAttr,
			Values: []string{
				user.Uid,
			},
		},
		{
			Name: alternateUserIdAttr,
			Values: []string{
				user.AltUid,
			},
		},
		{
			Name: CommonNameAttr,
			Values: []string{
				user.Cn,
			},
		},
		{
			Name: familyNameAttr,
			Values: []string{
				user.Sn,
			},
		},
		{
			Name: displayNameAttr,
			Values: []string{
				user.DisplayName,
			},
		},
		{
			Name: employeeNumberAttr,
			Values: []string{
				user.EmployeeNumber,
			},
		},
		{
			Name: mailAttr,
			Values: []string{
				user.Mail,
			},
		},
		{
			Name: statusAttr,
			Values: []string{
				user.Status,
			},
		},
	}
	um := usersManager{Client: NewClient(testConfig)}
	return &ldap.Entry{
		DN:         um.getDN(user.Uid),
		Attributes: attributes,
	}
}
