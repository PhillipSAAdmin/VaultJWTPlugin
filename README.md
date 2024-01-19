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
    [PRIVATE-KEY]
    [PUBLIC-KEY]

Role+[ROLE-ID]
    [ENGINE-ID]
    [Subject]
    [MAX_TTL]
    [ROLE]


CREDS -> How to Revoke -> You can't
Renew -> ???


        


