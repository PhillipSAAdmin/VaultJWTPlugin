package enumerations

// Create an Enumeration For All The Fields in EngineConfigStorage

type EngineConfigStorageFields string

const (
	EngineConfigStorageFields_Id              EngineConfigStorageFields = "Id"
	EngineConfigStorageFields_AllowedSubjects EngineConfigStorageFields = "AllowedSubjects"
	EngineConfigStorageFields_Issuer          EngineConfigStorageFields = "Issuer"
	EngineConfigStorageFields_Audience        EngineConfigStorageFields = "Audience"
	EngineConfigStorageFields_TTL             EngineConfigStorageFields = "TTL"
)

type EngineConfigKeyAbbrev string

const (
	EngineConfigKey EngineConfigKeyAbbrev = "EngineConfig" //+engine-id
)
