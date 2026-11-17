package directory

import "time"

// DirectoryIdentity is an AD object reference, scoped to an explicitly named
// directory. UPN/account name are current attributes, not immutable keys.
// A login snapshot never substitutes for revalidation at certificate issuance.
type DirectoryIdentity struct {
	DirectoryID string `json:"directory_id"`
	ObjectID    string `json:"object_id"` // hex of the 16 raw AD objectGUID bytes
	UPN         string `json:"upn"`
	AccountName string `json:"account_name"`
}

// DirectoryScope identifies a directory object, not a console role or owner.
// Mode is direct/nested for groups or direct/descendants for OUs.
type DirectoryScope struct {
	DirectoryID string
	ObjectID    string
	Kind        string
	Mode        string
	Name        string
	DN          string
}

type DirectoryScopeMatch struct {
	Scope   DirectoryScope
	Matches bool
}

type DirectoryScopeEvaluation struct {
	Owner     DirectoryIdentity
	CheckedAt time.Time
	Matches   []DirectoryScopeMatch
}
