package ldap

import (
	err "errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/ldap-go-lib/mocks"
	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
)

var (
	// Test LDAP Configuration
	testConfig = Config{
		Protocol:     "ldaps",
		Hostname:     "ldap.company.com",
		Port:         "636",
		BaseDN:       "company",
		UserBaseDN:   "ou=users,o=company",
		GroupBaseDN:  "ou=projects,o=company",
		BindUser:     "cn=root,o=company",
		BindPassword: "somePassword",
	}

	methodNameBind   = "Bind"
	methodNameClose  = "Close"
	methodNameSearch = "Search"
	methodNameAdd    = "Add"
	methodNameDelete = "Del"
	methodNameModify = "Modify"

	ldapInvalidCredentialsErr = ldap.NewError(ldap.LDAPResultInvalidCredentials, err.New(""))
	ldapInsufficientRightsErr = ldap.NewError(ldap.LDAPResultInsufficientAccessRights, err.New(""))
	ldapEntryAlreadyExistsErr = ldap.NewError(ldap.LDAPResultEntryAlreadyExists, err.New(""))
	ldapNoSuchObjectErr       = ldap.NewError(ldap.LDAPResultNoSuchObject, err.New(""))
	ldapNetworkErr            = ldap.NewError(ldap.ErrorNetwork, err.New(""))
)

func TestNewClient(t *testing.T) {
	client := NewClient(testConfig)
	assert.NotNil(t, client)
	assert.NotNil(t, client.Users)
	assert.NotNil(t, client.Groups)
	assert.NotNil(t, client.Users)
	assert.Equal(t, testConfig, client.Config)
}

func TestClient_SetProtocol(t *testing.T) {
	config := Config{}
	client := NewClient(config)

	t.Run("default protocol", func(t *testing.T) {
		assert.Equal(t, ProtocolLdaps, client.Config.Protocol)
	})

	t.Run("set valid protocol", func(t *testing.T) {
		client.SetProtocol(ProtocolLdap)
		assert.Equal(t, ProtocolLdap, client.Config.Protocol)
	})

	t.Run("set valid protocol", func(t *testing.T) {
		client.SetProtocol("test")
		assert.Equal(t, ProtocolLdaps, client.Config.Protocol)
	})
}

func TestClient_SetHostname(t *testing.T) {
	config := Config{}
	client := NewClient(config).SetHostname(testConfig.Hostname)
	assert.Equal(t, testConfig.Hostname, client.Config.Hostname)
}

func TestClient_SetPort(t *testing.T) {
	config := Config{}
	client := NewClient(config).SetPort(testConfig.Port)
	assert.Equal(t, testConfig.Port, client.Config.Port)
}

func TestClient_SetBindCredentials(t *testing.T) {
	config := Config{}
	client := NewClient(config).SetBindCredentials(testConfig.BindUser, testConfig.BindPassword)
	assert.Equal(t, testConfig.BindUser, client.Config.BindUser)
	assert.Equal(t, testConfig.BindPassword, client.Config.BindPassword)
}

func TestWithLDAPClient(t *testing.T) {
	ldapClient := new(ldap.Conn)
	client := NewClient(testConfig, WithLDAPClient(ldapClient))
	assert.Same(t, ldapClient, client.ldapClient)
}

func TestWithOrganisationUnitsManager(t *testing.T) {
	oum := new(organizationalUnitsManager)
	client := NewClient(testConfig, WithOrganisationUnitsManager(oum))
	assert.Same(t, oum, client.OrganizationalUnits)
}

func TestWithGroupsManager(t *testing.T) {
	gm := new(groupsManager)
	client := NewClient(testConfig, WithGroupsManager(gm))
	assert.Same(t, gm, client.Groups)
}

func TestWithUsersManager(t *testing.T) {
	um := new(usersManager)
	client := NewClient(testConfig, WithUsersManager(um))
	assert.Same(t, um, client.Users)
}

func TestUnitTesting(t *testing.T) {
	client := NewClient(testConfig, UnitTesting())
	assert.True(t, client.unitTesting)
}

func TestClient_connect(t *testing.T) {
	t.Run("validation error", func(t *testing.T) {
		config := Config{}
		client := NewClient(config)
		cErr := client.connect()
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, fmt.Sprintf(
			errors.ErrMsg[errors.ErrCodeMissingMandatoryConfiguration],
			[]string{
				"LDAP_HOSTNAME",
				"LDAP_PORT",
				"LDAP_BASE_DN",
				"LDAP_USER_BASE_DN",
				"LDAP_GROUP_BASE_DN",
				"bindUser",
				"bindPassword",
			}),
			cErr.Message,
		)
	})

	t.Run("dial error", func(t *testing.T) {
		client := NewClient(testConfig).SetProtocol(ProtocolLdap)
		cErr := client.connect()
		assert.Equal(t, errors.ErrCodeInternalServerError, cErr.Code)
		assert.Equal(t, http.StatusInternalServerError, cErr.Status)
		assert.Contains(t, cErr.Message, ldapNetworkErr.Error())
	})

	t.Run("dial error", func(t *testing.T) {
		client := NewClient(testConfig)
		cErr := client.connect()
		assert.Equal(t, errors.ErrCodeInternalServerError, cErr.Code)
		assert.Equal(t, http.StatusInternalServerError, cErr.Status)
		assert.Contains(t, cErr.Message, ldapNetworkErr.Error())
	})

	t.Run("bind error", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(ldapInvalidCredentialsErr)

		cErr := client.connect()
		assert.Equal(t, errors.ErrCodeUnauthorized, cErr.Code)
		assert.Equal(t, http.StatusUnauthorized, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials], cErr.Message)
	})

	t.Run("ldap search", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(ldapInvalidCredentialsErr)

		_, cErr := client.doLDAPSearch(&ldap.SearchRequest{})
		assert.Equal(t, errors.ErrCodeUnauthorized, cErr.Code)
		assert.Equal(t, http.StatusUnauthorized, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials], cErr.Message)
	})

	t.Run("ldap add", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(ldapInvalidCredentialsErr)

		cErr := client.doLDAPAdd(&ldap.AddRequest{})
		assert.Equal(t, errors.ErrCodeUnauthorized, cErr.Code)
		assert.Equal(t, http.StatusUnauthorized, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials], cErr.Message)
	})

	t.Run("ldap modify", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(ldapInvalidCredentialsErr)

		cErr := client.doLDAPModify(&ldap.ModifyRequest{})
		assert.Equal(t, errors.ErrCodeUnauthorized, cErr.Code)
		assert.Equal(t, http.StatusUnauthorized, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials], cErr.Message)
	})

	t.Run("ldap delete", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(ldapInvalidCredentialsErr)

		cErr := client.doLDAPDelete(&ldap.DelRequest{})
		assert.Equal(t, errors.ErrCodeUnauthorized, cErr.Code)
		assert.Equal(t, http.StatusUnauthorized, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials], cErr.Message)
	})

	t.Run("ldap password modify", func(t *testing.T) {
		ldapMock := mocks.NewClient(t)
		client := NewClient(testConfig, WithLDAPClient(ldapMock), UnitTesting())

		ldapMock.On(methodNameBind, testConfig.BindUser, testConfig.BindPassword).Return(ldapInvalidCredentialsErr)

		_, cErr := client.doLDAPPasswordModify(&ldap.PasswordModifyRequest{})
		assert.Equal(t, errors.ErrCodeUnauthorized, cErr.Code)
		assert.Equal(t, http.StatusUnauthorized, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials], cErr.Message)
	})
}

func TestClient_handleLdapError(t *testing.T) {
	client := NewClient(testConfig)

	t.Run("unauthorized error", func(t *testing.T) {
		cErr := client.handleLdapError(ldapInvalidCredentialsErr)
		assert.Equal(t, errors.ErrCodeUnauthorized, cErr.Code)
		assert.Equal(t, http.StatusUnauthorized, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInvalidCredentials], cErr.Message)
	})

	t.Run("forbidden error", func(t *testing.T) {
		cErr := client.handleLdapError(ldapInsufficientRightsErr)
		assert.Equal(t, errors.ErrCodeInsufficientAccess, cErr.Code)
		assert.Equal(t, http.StatusForbidden, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultInsufficientAccessRights], cErr.Message)
	})

	t.Run("bad request error", func(t *testing.T) {
		cErr := client.handleLdapError(ldapEntryAlreadyExistsErr)
		assert.Equal(t, errors.ErrCodeBadRequest, cErr.Code)
		assert.Equal(t, http.StatusBadRequest, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultEntryAlreadyExists], cErr.Message)
	})

	t.Run("not found error", func(t *testing.T) {
		cErr := client.handleLdapError(ldapNoSuchObjectErr)
		assert.Equal(t, errors.ErrCodeNotFound, cErr.Code)
		assert.Equal(t, http.StatusNotFound, cErr.Status)
		assert.Equal(t, ldap.LDAPResultCodeMap[ldap.LDAPResultNoSuchObject], cErr.Message)
	})

	t.Run("internal server error", func(t *testing.T) {
		cErr := client.handleLdapError(ldapNetworkErr)
		assert.Equal(t, errors.ErrCodeInternalServerError, cErr.Code)
		assert.Equal(t, http.StatusInternalServerError, cErr.Status)
		assert.Contains(t, cErr.Message, ldapNetworkErr.Error())
	})
}
