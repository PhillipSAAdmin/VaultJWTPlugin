package enumerations

// Create an Enumeration For All The Fields in RoleConfigStorage

type RoleConfigStorageFields string

const (
	RoleConfigRoleid   RoleConfigStorageFields = "roleid"
	RoleConfigTTL      RoleConfigStorageFields = "TTL"
	RoleConfigEngineId RoleConfigStorageFields = "EngineId"
	RoleConfigSubject  RoleConfigStorageFields = "Subject"
)

type RoleConfigAbbrevKey string

const (
	RoleConfigKey RoleConfigAbbrevKey = "RoleConfig" // + role-id
	PrivKeyKey    RoleConfigAbbrevKey = "PrivKey"    // + key-id
	PubKeyKey     RoleConfigAbbrevKey = "PubKey"     // + key-id
)
