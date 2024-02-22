package ldap

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/atselvan/go-utils/utils/errors"
	"github.com/atselvan/go-utils/utils/logger"
	"github.com/atselvan/go-utils/utils/slice"
	"github.com/go-ldap/ldap/v3"
)

const (
	noSuchUserGroupMemberCn               = "NO_SUCH_USER"
	groupAlreadyExistsMsg                 = "Group with cn = '%s' and ou = '%s' already exists"
	groupNotFoundMsg                      = "Group with cn = '%s' and ou = '%s' was not found"
	invalidOrganizationalUnitErrMsg       = "Invalid organizational unit '%s'. Valid values are %v"
	uniqueMemberWillBeAddedToGroupMsg     = "UniqueMember '%s' will be added to the group '%s'"
	uniqueMemberWillBeRemovedFromGroupMsg = "UniqueMember '%s' will be removed from the group '%s'"
)

type (
	// GroupsManager describes the interface that needs to be implemented for performing operations on LDAP groups.
	GroupsManager interface {
		GetAll() ([]Group, *errors.Error)
		Get(cn, ou string) ([]Group, *errors.Error)
		GetFilter(searchFilter string) ([]Group, *errors.Error)
		Create(cn, ou string, memberIds []string) *errors.Error
		Delete(cn, ou string) *errors.Error
		AddMembers(cn, ou string, memberIds []string) *errors.Error
		RemoveMembers(cn, ou string, memberIds []string) *errors.Error
	}

	// groupsManager implements GroupsManager.
	groupsManager struct {
		Client *Client
	}

	// Group represents an LDAP group.
	Group struct {
		Dn      string
		Ou      string
		Cn      string
		Members []string
	}
)

// GetAll retrieves all the group entries from the groupBaseDn set in the client Config
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsManager) GetAll() ([]Group, *errors.Error) {
	return gm.Get("", "")
}

// Get retrieves a list of group entries from LDAP.
// The list of groups depends on the input values of cn and ou.
// params:
//
//	cn = common name of the group
//	ou = organization unit within which the group is contained
//
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsManager) Get(cn, ou string) ([]Group, *errors.Error) {
	if ou != "" {
		if cErr := gm.validateGroupOu(ou); cErr != nil {
			return nil, cErr
		}
	}
	result, cErr := gm.Client.doLDAPSearch(gm.getSearchRequest(cn, ou, groupSearchFilter))
	if cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return nil, errors.NotFoundError(fmt.Sprintf(groupNotFoundMsg, cn, ou))
		}
		return nil, cErr
	}
	return gm.parseSearchResult(result), nil
}

// GetFilter will filter and get a list of group entries based on the searchFilter
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsManager) GetFilter(searchFilter string) ([]Group, *errors.Error) {
	result, err := gm.Client.doLDAPSearch(gm.getSearchRequest("", "", searchFilter))

	if err != nil {
		return nil, err
	}
	return gm.parseSearchResult(result), nil
}

// Create adds a new group entry in LDAP
// Params:
//
//	cn: name of the group
//	ou: organizational unit under which the group should be created
//	memberIds: a list of memberIds to be added as a unique member in the group
//
// If NO memberIds are provided then a default unique member NO_SUCH_USER will be added to the group during creation.
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group already exists
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsManager) Create(cn, ou string, memberIds []string) *errors.Error {
	if err := gm.validateGroup(cn, ou); err != nil {
		return err
	}
	if len(memberIds) == 0 {
		memberIds = append(memberIds, noSuchUserGroupMemberCn)
	}
	if cErr := gm.Client.doLDAPAdd(gm.getAddRequest(cn, ou, memberIds)); cErr != nil {
		if cErr.Status == http.StatusBadRequest {
			return errors.ConflictError(fmt.Sprintf(groupAlreadyExistsMsg, cn, ou))
		} else {
			return cErr
		}
	}
	return nil
}

// Delete adds an existing group entry from LDAP
// Params:
//
//	cn: name of the group
//	ou: organizational unit under which the group should be created
//
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsManager) Delete(cn, ou string) *errors.Error {
	if err := gm.validateGroup(cn, ou); err != nil {
		return err
	}
	if cErr := gm.Client.doLDAPDelete(gm.getDeleteRequest(cn, ou)); cErr != nil {
		if cErr.Status == http.StatusNotFound {
			return errors.NotFoundError(fmt.Sprintf(groupNotFoundMsg, cn, ou))
		} else {
			return cErr
		}
	}
	return nil
}

// AddMembers add uniqueMember(s) to an existing group entry in LDAP
// Params:
//
//	cn: name of the group
//	ou: organizational unit under which the group exists
//	memberIds: a list of memberIds to be added as a unique member in the group
//
// If NO memberIds are provided then there will be no change.
// If there are more than one valid member in the group then the default unique member NO_SUCH_USER will be
// removed from the group during the update.
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsManager) AddMembers(cn, ou string, memberIds []string) *errors.Error {
	var uniqueMembers []string
	if err := gm.validateGroup(cn, ou); err != nil {
		return err
	}
	result, cErr := gm.Get(cn, ou)
	if cErr != nil {
		return cErr
	}
	group := result[0]
	mr := gm.getModifyRequest(cn, ou)
	for _, memberId := range memberIds {
		uniqueMember := gm.getUniqueMemberDn(strings.ToUpper(memberId))
		if !slice.EntryExists(group.Members, uniqueMember) {
			logger.Info(fmt.Sprintf(uniqueMemberWillBeAddedToGroupMsg, uniqueMember, gm.getDN(cn, ou)))
			uniqueMembers = append(uniqueMembers, uniqueMember)
		}
	}
	if len(uniqueMembers) > 0 {
		mr.Add(uniqueMemberAttr, uniqueMembers)
	}
	if len(group.Members)+len(uniqueMembers) >= 2 {
		uniqueMember := gm.getUniqueMemberDn(noSuchUserGroupMemberCn)
		mr.Delete(uniqueMemberAttr, []string{uniqueMember})
	}
	if cErr := gm.Client.doLDAPModify(mr); cErr != nil {
		return cErr
	}
	return nil
}

// RemoveMembers removes existing uniqueMember(s) from an existing group entry in LDAP
// Params:
//
//	cn: name of the group
//	ou: organizational unit under which the group exists
//	memberIds: a list of memberIds to be added as a unique member in the group
//
// If NO memberIds are provided then there will be no change.
// If there are no more valid member in the group, the default unique member NO_SUCH_USER will be
// added to the group during the update.
// The method returns an error:
//   - if any validation fails
//   - if the organizational unit is not found
//   - if the group is not found
//   - if there is a connection/network issue while opening a connection with LDAP
//   - if the query to LDAP fails
func (gm *groupsManager) RemoveMembers(cn, ou string, memberIds []string) *errors.Error {
	var uniqueMembers []string
	if err := gm.validateGroup(cn, ou); err != nil {
		return err
	}
	result, cErr := gm.Get(cn, ou)
	if cErr != nil {
		return cErr
	}
	group := result[0]
	mr := gm.getModifyRequest(cn, ou)
	for _, memberId := range memberIds {
		uniqueMember := gm.getUniqueMemberDn(strings.ToUpper(memberId))
		if slice.EntryExists(group.Members, uniqueMember) {
			if memberId != noSuchUserGroupMemberCn {
				logger.Info(fmt.Sprintf(uniqueMemberWillBeRemovedFromGroupMsg, uniqueMember, gm.getDN(cn, ou)))
			}
			uniqueMembers = append(uniqueMembers, uniqueMember)
		}
	}
	if len(uniqueMembers) > 0 {
		mr.Delete(uniqueMemberAttr, uniqueMembers)
	}
	if len(group.Members)-len(uniqueMembers) == 0 {
		uniqueMember := gm.getUniqueMemberDn(strings.ToUpper(noSuchUserGroupMemberCn))
		mr.Add(uniqueMemberAttr, []string{uniqueMember})
	}
	if cErr := gm.Client.doLDAPModify(mr); cErr != nil {
		return cErr
	}
	return nil
}

// getDN returns the formatted domain name of a ldap group
func (gm *groupsManager) getDN(cn, ou string) string {
	if cn != "" && ou != "" {
		return fmt.Sprintf("%s=%s,%s=%s,%s", CommonNameAttr, cn, OrganizationalUnitAttr, ou,
			gm.Client.Config.GroupBaseDN)
	} else if cn == "" && ou != "" {
		return fmt.Sprintf("%s=%s,%s", OrganizationalUnitAttr, ou, gm.Client.Config.GroupBaseDN)
	} else {
		return gm.Client.Config.GroupBaseDN
	}
}

// getUniqueMemberDn returns the formatted unique member domain name
func (gm *groupsManager) getUniqueMemberDn(memberId string) string {
	return fmt.Sprintf("%s=%s,%s", userIdAttr, memberId, gm.Client.Config.UserBaseDN)
}

// getSearchRequest returns a ldap search request
func (gm *groupsManager) getSearchRequest(cn, ou, groupSearchFilter string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(
		gm.getDN(cn, ou),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		groupSearchFilter,
		[]string{
			CommonNameAttr,
			uniqueMemberAttr,
		},
		nil,
	)
}

func (gm *groupsManager) getAddRequest(cn, ou string, memberIds []string) *ldap.AddRequest {
	var uniqueMembers []string
	for _, memberId := range memberIds {
		uniqueMember := gm.getUniqueMemberDn(strings.ToUpper(memberId))
		uniqueMembers = append(uniqueMembers, uniqueMember)
	}
	dn := gm.getDN(cn, ou)
	ar := ldap.NewAddRequest(dn, nil)
	ar.Attribute(objectClassAttr, defaultObjectClassesGroup)
	ar.Attribute(CommonNameAttr, []string{cn})
	ar.Attribute(uniqueMemberAttr, uniqueMembers)
	return ar
}

func (gm *groupsManager) getModifyRequest(cn, ou string) *ldap.ModifyRequest {
	return ldap.NewModifyRequest(gm.getDN(cn, ou), nil)
}

func (gm *groupsManager) getDeleteRequest(cn, ou string) *ldap.DelRequest {
	return ldap.NewDelRequest(gm.getDN(cn, ou), nil)
}

// parseSearchResult parses the ldap search result and retrieves the group entries.
func (gm *groupsManager) parseSearchResult(result *ldap.SearchResult) []Group {
	var groups []Group
	for _, entry := range result.Entries {
		group := Group{
			Dn:      entry.DN,
			Ou:      strings.Replace(strings.Split(entry.DN, ",")[1], OrganizationalUnitAttrValuePrefix, "", -1),
			Cn:      entry.GetAttributeValue(CommonNameAttr),
			Members: entry.GetAttributeValues(uniqueMemberAttr),
		}
		groups = append(groups, group)
	}
	return groups
}

// validateGroup checks if required information is provided for a ldap group
func (gm *groupsManager) validateGroup(cn, ou string) *errors.Error {
	var missingParams []string

	if strings.TrimSpace(cn) == "" {
		missingParams = append(missingParams, CommonNameAttr)
	}
	if strings.TrimSpace(ou) == "" {
		missingParams = append(missingParams, OrganizationalUnitAttr)
	}
	if len(missingParams) > 0 {
		return errors.BadRequestErrorf(errors.ErrMsg[errors.ErrCodeMissingMandatoryParameter], missingParams)
	}
	if err := gm.validateGroupOu(ou); err != nil {
		return err
	}
	return nil
}

// validateGroupOu checks if the ldap organizational unit is valid
func (gm *groupsManager) validateGroupOu(ou string) *errors.Error {
	organizationalUnits, cErr := gm.Client.OrganizationalUnits.GetAll()
	if cErr != nil {
		return cErr
	}
	if !slice.EntryExists(organizationalUnits, ou) {
		return errors.BadRequestError(fmt.Sprintf(invalidOrganizationalUnitErrMsg, ou, organizationalUnits))
	}
	return nil
}
