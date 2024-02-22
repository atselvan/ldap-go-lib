package ldap

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/go-utils/utils/slice"
	"github.com/go-ldap/ldap/v3"
)

const (
	UserStatusActive   = "Active"
	UserStatusDisabled = "Disabled"
	UserStatusRevoked  = "Revoked"
	UserStatusDeleted  = "Deleted"

	UserTypePersonal = "personal"
	UserTypeNPA      = "npa"
	UserTypeBuilder  = "builder"

	userAlreadyExistsMsg   = "User with uid = '%s' already exists"
	userNotFoundMsg        = "User with uid = '%s' was not found"
	invalidStatusErrMsg    = "Invalid status '%s'. Valid status's are %v"
	invalidUserTypeErrMsg  = "Invalid type '%s'. Valid types are %v"
	invalidFilterKeyErrMsg = "Invalid filter key '%s'. Valid filter keys are %v"
)

var (
	PersonalUserTypeRegex    = "^[A-Za-z]{1,2}[0-9]{4,5}[A-Za-z]{0,1}|^[A-Za-z]{4,5}$|^[A-Za-z]{2,3}[0-9]{1,2}$"
	BuilderAccountSuffix     = "_BUILDER"
	BuilderAccountTypeFilter = "*" + BuilderAccountSuffix

	validStatusList = []string{
		UserStatusActive,
		UserStatusDisabled,
		UserStatusRevoked,
		UserStatusDeleted,
	}

	validUserTypes = []string{
		UserTypePersonal,
		UserTypeNPA,
		UserTypeBuilder,
	}

	userAttributes = []string{
		userIdAttr,
		alternateUserIdAttr,
		CommonNameAttr,
		familyNameAttr,
		displayNameAttr,
		employeeNumberAttr,
		mailAttr,
		statusAttr,
	}
)

type (
	// UsersManager describes an interface the needs to be implemented for performing operations on
	// all user accounts in LDAP.
	UsersManager interface {
		GetAll() ([]User, *errors.Error)
		Get(uid string) (*User, *errors.Error)
		Filter(key, value string) ([]User, *errors.Error)
		FilterByStatus(status string) ([]User, *errors.Error)
		FilterByType(userType string) ([]User, *errors.Error)
		Create(user User) *errors.Error
		Delete(uid string) *errors.Error
		Authenticate() *errors.Error
		SetNewPassword(uid, newPassword string) (string, *errors.Error)
	}

	// usersManager implements the UsersManager interface.
	usersManager struct {
		Client *Client
	}

	// User represents the attributes of a user in LDAP
	User struct {
		Uid            string `json:"uid" form:"uid" required:"true"`
		AltUid         string `json:"atlUid" form:"atlUid" required:"true"`
		Cn             string `json:"cn" form:"cn" required:"true"`
		Sn             string `json:"sn" form:"sn" required:"true"`
		DisplayName    string `json:"displayName" form:"displayName" required:"true"`
		EmployeeNumber string `json:"employeeNumber,omitempty" form:"employeeNumber" required:"true"`
		Mail           string `json:"mail" form:"mail" required:"true"`
		UserPassword   string `json:"userPassword,omitempty" form:"userPassword" required:"true"`
		Status         string `json:"status" form:"status" required:"true"`
	}
)

// GetAll retrieves all the user entries from LDAP.
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) GetAll() ([]User, *errors.Error) {
	sr := um.getUsersSearchRequest(userSearchFilter)
	result, err := um.Client.doLDAPSearch(sr)
	if err != nil {
		return nil, err
	}
	return um.parseSearchResult(result), nil
}

// Get retrieves a single user's entry from LDAP.
// params:
//
//	uid = user identifier
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) Get(uid string) (*User, *errors.Error) {
	if cErr := um.validateUid(uid); cErr != nil {
		return nil, cErr
	}
	sr := um.getUserSearchRequest(um.getDN(uid))
	result, cErr := um.Client.doLDAPSearch(sr)
	if cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return nil, errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, uid))
		}
		return nil, cErr
	}
	return &(um.parseSearchResult(result))[0], nil
}

// Filter retrieves a list of user entries from LDAP which is filtered based on the filter passed to the method
// as input. The filter is represented by a key and a value.
// params:
//
//	key 	= The key of the filter
//	value 	=  The value of the filter
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) Filter(key, value string) ([]User, *errors.Error) {
	if cErr := um.validateFilter(key, value); cErr != nil {
		return nil, cErr
	}
	userSearchFilter := fmt.Sprintf(WildcardUserSearchFilter, key, value)
	sr := um.getUsersSearchRequest(userSearchFilter)
	result, err := um.Client.doLDAPSearch(sr)
	if err != nil {
		return nil, err
	}
	return um.parseSearchResult(result), nil
}

// FilterByStatus retrieves a list of user entries from LDAP which is filtered based on the status of the user entry.
// params:
//
//	status = the status of a user record
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) FilterByStatus(status string) ([]User, *errors.Error) {
	if cErr := um.validateStatus(status); cErr != nil {
		return nil, cErr
	}
	return um.Filter(statusAttr, status)
}

// FilterByType retrieves all the user entries from LDAP and then filters the list based on the type of the user.
// params:
//
//	userType = the type of the user record
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) FilterByType(userType string) ([]User, *errors.Error) {
	switch userType {
	case UserTypePersonal:
		return um.getPersonalAccounts()
	case UserTypeBuilder:
		return um.getBuilderAccounts()
	case UserTypeNPA:
		return um.getNPAAccounts()
	default:
		return nil, errors.BadRequestError(fmt.Sprintf(invalidUserTypeErrMsg, userType, validUserTypes))
	}
}

// Create a new user entry in LDAP.
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) Create(user User) *errors.Error {
	if cErr := um.validateUser(user); cErr != nil {
		return cErr
	}

	ar := um.getAddRequest(user)

	if cErr := um.Client.doLDAPAdd(ar); cErr != nil {
		if cErr.Status == http.StatusBadRequest {
			return errors.ConflictError(fmt.Sprintf(userAlreadyExistsMsg, user.Uid))
		} else {
			return cErr
		}
	}

	if _, cErr := um.modifyPassword(user.Uid, user.UserPassword, user.UserPassword); cErr != nil {
		return cErr
	}

	return nil
}

// Delete an existing user entry from LDAP.
// param:
//
//	uid = user identifier
//
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) Delete(uid string) *errors.Error {
	if cErr := um.validateUid(uid); cErr != nil {
		return cErr
	}
	dr := um.getDeleteRequest(uid)
	if cErr := um.Client.doLDAPDelete(dr); cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, uid))
		} else {
			return cErr
		}
	}
	return nil
}

// Authenticate check if a user account can authenticate to LDAP.
// The bind credentials set using client.SetBindCredentials will be used to authenticating to LDAP.
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) Authenticate() *errors.Error {
	return um.Client.connect()
}

// SetNewPassword sets a new password for an existing user entry in LDAP.
// param:
//
//	uid 		= user identifier
//	newPassword = a new password to be set for the user
//
// If newPassword is empty then a new password will be generated for the user. The generated
// password will be updated for the user account and will be returned by the method.
// The method returns an error:
//   - if a validation fails
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (um *usersManager) SetNewPassword(uid, newPassword string) (string, *errors.Error) {
	if newPassword == "" {
		result, cErr := um.modifyPassword(uid, "", "")
		if cErr != nil {
			return "", cErr
		}
		return result.GeneratedPassword, nil
	} else {
		_, cErr := um.modifyPassword(uid, "", newPassword)
		if cErr != nil {
			return "", cErr
		}
		return newPassword, nil
	}
}

// getDN returns the formatted LDAP user domain name.
func (um *usersManager) getDN(uid string) string {
	return fmt.Sprintf("%s=%s,%s", userIdAttr, uid, um.Client.Config.UserBaseDN)
}

// getUsersSearchRequest returns a ldap search request to get a list of users.
// The list of users retrieved depends on the userSearchFilter.
func (um *usersManager) getUsersSearchRequest(userSearchFilter string) *ldap.SearchRequest {
	return &ldap.SearchRequest{
		BaseDN:       um.Client.Config.UserBaseDN,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       userSearchFilter,
		Attributes:   userAttributes,
		Controls:     nil,
	}
}

// getUserSearchRequest returns a ldap search request to get a single user entry.
func (um *usersManager) getUserSearchRequest(DN string) *ldap.SearchRequest {
	return &ldap.SearchRequest{
		BaseDN:       DN,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       userSearchFilter,
		Attributes:   userAttributes,
		Controls:     nil,
	}
}

// getAddRequest returns a ldap add request to add a new user entry.
func (um *usersManager) getAddRequest(user User) *ldap.AddRequest {
	ar := ldap.NewAddRequest(um.getDN(user.Uid), nil)
	ar.Attribute(objectClassAttr, defaultObjectClassesUser)
	ar.Attribute(userIdAttr, []string{user.Uid})
	ar.Attribute(alternateUserIdAttr, []string{user.AltUid})
	ar.Attribute(CommonNameAttr, []string{user.Cn})
	ar.Attribute(familyNameAttr, []string{user.Sn})
	ar.Attribute(displayNameAttr, []string{user.DisplayName})
	ar.Attribute(employeeNumberAttr, []string{user.EmployeeNumber})
	ar.Attribute(mailAttr, []string{user.Mail})
	ar.Attribute(userPasswordAttr, []string{user.UserPassword})
	ar.Attribute(statusAttr, []string{user.Status})
	return ar
}

// getPasswordModifyRequest returns a ldap password modify request.
func (um *usersManager) getPasswordModifyRequest(uid, oldPassword, newPassword string) *ldap.PasswordModifyRequest {
	return ldap.NewPasswordModifyRequest(
		um.getDN(uid),
		oldPassword,
		newPassword,
	)
}

// getDeleteRequest return a ldap delete request.
func (um *usersManager) getDeleteRequest(uid string) *ldap.DelRequest {
	return ldap.NewDelRequest(um.getDN(uid), nil)
}

// parseSearchResult parses the result of the LDAP user search query.
func (um *usersManager) parseSearchResult(result *ldap.SearchResult) []User {
	var users []User
	for _, e := range result.Entries {
		user := User{
			Uid:            e.GetAttributeValue(userIdAttr),
			AltUid:         e.GetAttributeValue(alternateUserIdAttr),
			Cn:             e.GetAttributeValue(CommonNameAttr),
			Sn:             e.GetAttributeValue(familyNameAttr),
			DisplayName:    e.GetAttributeValue(displayNameAttr),
			EmployeeNumber: e.GetAttributeValue(employeeNumberAttr),
			Mail:           e.GetAttributeValue(mailAttr),
			UserPassword:   e.GetAttributeValue(userPasswordAttr),
			Status:         e.GetAttributeValue(statusAttr),
		}
		users = append(users, user)
	}
	if len(users) == 0 {
		return []User{}
	}
	return users
}

// getPersonalAccounts retrieves all the users from LDAP and then filters for the personal accounts based on the
// PersonalUserTypeRegex regular expression.
func (um *usersManager) getPersonalAccounts() ([]User, *errors.Error) {
	var result []User
	cRegex, err := regexp.Compile(PersonalUserTypeRegex)
	if err != nil {
		return nil, errors.InternalServerError(err.Error())
	}
	users, cErr := um.GetAll()
	if cErr != nil {
		return nil, cErr
	}
	for _, user := range users {
		if cRegex.Match([]byte(user.Uid)) {
			result = append(result, user)
		}
	}
	return result, nil
}

// getBuilderAccounts retrieves all the builder accounts from LDAP using the Filter method and the
// BuilderAccountTypeFilter.
func (um *usersManager) getBuilderAccounts() ([]User, *errors.Error) {
	return um.Filter(userIdAttr, BuilderAccountTypeFilter)
}

// getNPAAccounts retrieves all the users from LDAP. The personal accounts and the builder accounts are filtered out
// of the list and the remainder of the accounts are returned.
func (um *usersManager) getNPAAccounts() ([]User, *errors.Error) {
	var result []User
	cRegex, err := regexp.Compile(PersonalUserTypeRegex)
	if err != nil {
		return nil, errors.InternalServerError(err.Error())
	}
	users, cErr := um.GetAll()
	if cErr != nil {
		return nil, cErr
	}
	for _, user := range users {
		if !cRegex.Match([]byte(user.Uid)) && !strings.Contains(user.Uid, BuilderAccountSuffix) {
			result = append(result, user)
		}
	}
	return result, nil
}

// modifyPassword processes the ldap password modify request.
func (um *usersManager) modifyPassword(uid, oldPassword, newPassword string) (*ldap.PasswordModifyResult, *errors.Error) {
	pmr := um.getPasswordModifyRequest(uid, oldPassword, newPassword)
	result, cErr := um.Client.doLDAPPasswordModify(pmr)
	if cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return nil, errors.NotFoundError(fmt.Sprintf(userNotFoundMsg, uid))
		} else {
			return nil, cErr
		}
	}
	return result, nil
}

// validateUid checks if the uid is set.
func (um *usersManager) validateUid(uid string) *errors.Error {
	if strings.TrimSpace(uid) == "" {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], []string{userIdAttr})
	}
	return nil
}

// validateUser checks if all the required attributes of a User are set for creating a new user.
func (um *usersManager) validateUser(user User) *errors.Error {

	var missingParams []string

	if strings.TrimSpace(user.Uid) == "" {
		missingParams = append(missingParams, userIdAttr)
	}
	if strings.TrimSpace(user.AltUid) == "" {
		missingParams = append(missingParams, alternateUserIdAttr)
	}
	if strings.TrimSpace(user.Cn) == "" {
		missingParams = append(missingParams, CommonNameAttr)
	}
	if strings.TrimSpace(user.Sn) == "" {
		missingParams = append(missingParams, familyNameAttr)
	}
	if strings.TrimSpace(user.DisplayName) == "" {
		missingParams = append(missingParams, displayNameAttr)
	}
	if strings.TrimSpace(user.Mail) == "" {
		missingParams = append(missingParams, mailAttr)
	}
	if strings.TrimSpace(user.UserPassword) == "" {
		missingParams = append(missingParams, userPasswordAttr)
	}
	if strings.TrimSpace(user.Status) == "" {
		missingParams = append(missingParams, statusAttr)
	}

	if len(missingParams) > 0 {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], missingParams)
	}
	if cErr := um.validateStatus(user.Status); cErr != nil {
		return cErr
	}
	return nil
}

// validateFilter checks if the filter key and value is set.
func (um *usersManager) validateFilter(key, value string) *errors.Error {
	var missingParams []string
	if strings.TrimSpace(key) == "" {
		missingParams = append(missingParams, "key")
	}
	if strings.TrimSpace(value) == "" {
		missingParams = append(missingParams, "value")
	}
	if len(missingParams) > 0 {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], missingParams)
	}
	if !slice.EntryExists(userAttributes, key) {
		return errors.BadRequestError(fmt.Sprintf(invalidFilterKeyErrMsg, key, userAttributes))
	}
	return nil
}

// validateStatus checks if the status attribute value is valid.
func (um *usersManager) validateStatus(status string) *errors.Error {
	if !slice.EntryExists(validStatusList, status) {
		return errors.BadRequestError(fmt.Sprintf(invalidStatusErrMsg, status, validStatusList))
	}
	return nil
}
