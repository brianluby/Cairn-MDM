package auth

// DirectoryIdentity is an AD object reference, scoped to an explicitly named
// directory. UPN/account name are current attributes, not immutable keys.
// A login snapshot never substitutes for revalidation at certificate issuance.
type DirectoryIdentity struct {
	DirectoryID string `json:"directory_id"`
	ObjectID    string `json:"object_id"` // hex of the 16 raw AD objectGUID bytes
	UPN         string `json:"upn"`
	AccountName string `json:"account_name"`
}
