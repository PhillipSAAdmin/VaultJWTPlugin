# Plugin Outline 

## Per Engine Configuration 

Configure a JWT "Issuer"
AT 
{engine-name}/config/{engine_id}

This Includes 
[Audience]
[Issuer]
[Allowed_Subjects]
[Default_Token_Exp]

## Per Role Configuration

Configure a Role 
AT 
{engine-name}/role/{role-name}
SUCH AS 
[Engine-ID]
[Subject]
[MAX_TTL] (DEFAULTS TO Engine)
[ROLE]


## GET Credentials
{engine-name}/creds/{role-name}


## Public Information
{engine-name}/{engine-id}/public

Returns Public Key IDs Corresponding to Private KEys

## Plugin Data Configuration and Keys

[Engine+Engine-ID]
    [Issuer]
    [Audience]
    [Allowed-Subjects]
    [Default_Token_Exp]
Engine-ID+keys:[]
    [ID]
    [PRIVATE-KEY] (Deprecated)
    [PUBLIC-KEY] (Deprecated)

Role+[ROLE-ID]
    [ENGINE-ID]
    [Subject]
    [MAX_TTL]
    [ROLE]

Credentials
    Each Lease
        Has A Keyid
        And a Token
    [privkey+uuid]
    [publickey+uuid]

    Lease Time : Max of Requested_TTL, Engine Configured TTL, Role MAX_TTL

    Renewal -> Sign a New JWT With Initial Lease Options

    Revocation -> Remove the Public Key From Storage -> Just For Now .... Need another way of verifying the Token 




Example With Vault Dev:
    go build -o jwks_plugin
    cp jwks_plugin /.vault/plugins/plugin

    vault server -dev -dev-plugin-dir=/.vault/plugins
    export VAULT_ADDR="http://127.0.0.1:8200"
    vault secrets enable -path=/jwks_plugin -plugin-name=mypugin plugin

    // Set Engine Config, id = cook
    vault write myplugin/config/cook Allowed_Subjects="vault,user,sice" Issuer=vault Audience=vault TTL=3600

    // Set Config For Role row, subject = bob 
     vault write myplugin/role/row  TTL=1000 Subject=bob EngineId=cook

     // Get Credentials With Read Access
     vault read myplugin/cred/row  Requested_TTL=20


