# Development LDAP Go Library

A golang library for connection to and interacting with the development ldap server.

[[_TOC_]]

## Features
* Read all organization unit entries.
* Get all user entries.
* Filter user entries based on status.
* Filter user entries based on user type.
* Filter user entries based on custom filters.
* Create and delete LDAP user entries.
* Set a new password for a user entry.
* Set a new generated password for a user entry.
* Get all the group entries.
* Filter group entries based on a custom filter.
* Create and delete LDAP group entries.
* Add new members to a group entry.
* Remove existing members from a group entry.

## Usage

### Create a new LDAP client

```go
import "github.com/atselvan/ldap-go-lib/ldap"

config = ldap.Config{
    Protocol:     "ldaps",
    Hostname:     "ldap.company.com",
    Port:         "636",
    BaseDN:       "company",
    UserBaseDN:   "ou=users,o=company",
    GroupBaseDN:  "ou=projects,o=company",
    BindUser:     "cn=root,o=company",
    BindPassword: "somePassword",
}

client := ldap.NewClient(config)
```

### Get organisation unit entries

```go
// get all organization unit entries
organizationUnits, cErr := client.OrganizationalUnits.GetAll()
```

### Get user entries

```go
// get all user entries
users, cErr := client.Users.GetAll()

// get a user entry that matches the userId
user, cErr := client.Users.Get("C00001")

// get all user entries with the Active status
users, cErr := client.Users.FilterByStatus("Active")

// get all user entries which are of the type personal
users, cErr := client.Users.FilterByType("personal")

// get all users entries based on a custom filter key and value
users, cErr := client.Users.Filter("filterKey", "filterValue")
```

### Create a new user

```go
user := ldap.User{
	Uid:            "C00001",
	AltUid:         "john.doe",
	Cn:             "John",
	Sn:             "Doe",
	DisplayName:    "John Doe",
	EmployeeNumber: "E100001",
	Mail:           "john.doe@company.com",
	Status:         ldap.UserStatusActive,
	UserPassword:   "somePassword",
}
cErr := client.Users.Create(user)
```

### Delete an existing user

```go
cErr := client.Users.Delete("C00001")
```

### Set new password for a user

```go
// set a new custom password for the user entry
cErr := client.Users.SetNewPassword("C00001", "somePassword")

// set a new generated password for the user entry
cErr := client.Users.SetNewPassword("C00001", "")
```

### Get group entries

```go
// get all group entries
groups, cErr := client.Groups.GetAll()

// get all group entries within a specific orgUnit
groups, cErr := client.Groups.Get("", "orgUnit")

// get a group entry that matches the groupName within a specific orgUnit
groups, cErr := client.Groups.Get("groupName", "orgUnit")
```

### Create a new group

```go
cErr := client.Groups.Create("groupName", "orgUnit", []string{"member1", "member2"})
```

### Delete an existing group

```go
cErr := client.Groups.Delete("groupName", "orgUnit")
```

### Add new member(s) to a group

```go
cErr := client.Groups.AddMembers("groupName", "orgUnit", []string{"member3"})
```

### Remove existing member(s) from a group

```go
cErr := client.Groups.RemoveMembers("groupName", "orgUnit", []string{"member3"})
```