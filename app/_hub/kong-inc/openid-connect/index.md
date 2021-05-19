---
name: OpenID Connect
publisher: Kong Inc.
version: 2.0.x

desc: Integrate Kong with a third-party OpenID Connect provider
description: |
  OpenID Connect ([1.0][connect]) plugin allows the integration with a 3rd party
  identity provider (IdP) in a standardized way. This plugin can be used to implement
  Kong as a (proxying) [OAuth 2.0][oauth2] resource server (RS) and/or as an OpenID
  Connect relying party (RP) between the client, and the upstream service.

  The plugin supports several types of credentials and grants:

  - Signed [JWT][jwt] access tokens ([JWS][jws])
  - Opaque access tokens
  - Refresh tokens
  - Authorization code  
  - Username and password
  - Client credentials
  - Session cookies

  The plugin has been tested with several OpenID Connect providers:

  - [Auth0][auth0]
  - [Amazon AWS Cognito][cognito]
  - [Connect2id][connect2id]
  - [Curity][curity]
  - [Dex][dex]
  - [Gluu][gluu]
  - [Google][google]
  - [IdentityServer4][identityserver4]
  - [Keycloak][keycloak]
  - [Microsoft Azure Active Directory][azure], and [Active Directory Federation Services][adfs]
  - [Okta][okta]
  - [OneLogin][onelogin]
  - [OpenAM][openam]
  - [Paypal][paypal]
  - [PingFederate][pingfederate]
  - [Salesforce][salesforce]
  - [Yahoo!][yahoo]

  As long as your provider supports OpenID Connect, OAuth or JWT standards,
  the plugin should work, even if it is not specifically tested against it.
  Let Kong know if you want your provider to be tested and added to the list.

  [connect]: http://openid.net/specs/openid-connect-core-1_0.html
  [oauth2]: https://tools.ietf.org/html/rfc6749
  [jwt]: https://tools.ietf.org/html/rfc7519
  [jws]: https://tools.ietf.org/html/rfc7515
  [auth0]: https://auth0.com/docs/protocols/openid-connect-protocol
  [cognito]: https://aws.amazon.com/cognito/
  [connect2id]: https://connect2id.com/products/server
  [curity]: https://curity.io/resources/learn/openid-connect-overview/
  [dex]: https://dexidp.io/docs/openid-connect/
  [gluu]: https://gluu.org/docs/ce/api-guide/openid-connect-api/
  [google]: https://developers.google.com/identity/protocols/oauth2/openid-connect
  [identityserver4]: https://identityserver4.readthedocs.io/
  [keycloak]: http://www.keycloak.org/documentation.html
  [azure]: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
  [adfs]: https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-openid-connect-oauth-concepts
  [okta]: https://developer.okta.com/docs/api/resources/oidc.html
  [onelogin]: https://developers.onelogin.com/openid-connect
  [openam]: https://backstage.forgerock.com/docs/openam/13.5/admin-guide/#chap-openid-connect
  [paypal]: https://developer.paypal.com/docs/log-in-with-paypal/integrate/
  [pingfederate]: https://documentation.pingidentity.com/pingfederate/
  [salesforce]: https://help.salesforce.com/articleView?id=sf.sso_provider_openid_connect.htm&type=5
  [yahoo]: https://developer.yahoo.com/oauth2/guide/openid_connect/

  Once applied, any user with a valid credential can access the Service.

  This plugin can be used for authentication in conjunction with the
  [Application Registration](/hub/kong-inc/application-registration) plugin.

enterprise: true
plus: true
type: plugin
categories:
  - authentication

kong_version_compatibility:
    community_edition:
      compatible:
    enterprise_edition:
      compatible:
        - 2.4.x
        - 2.3.x
        - 2.2.x

params:
  name: openid-connect
  service_id: true
  route_id: true
  consumer_id: false
  protocols: [ "http", "https", "grpc (depends on grant)", "grpcs (depends on grant)" ]
  dbless_compatible: yes
  config:
    - group: Authentication Grants
    - name: auth_methods
      required: false
      default: [ "password", "client_credentials", "authorization_code", "bearer", "introspection", "userinfo", "kong_oauth2", "refresh_token", "session" ]
      value_in_examples: [ "authorization_code", "session" ]
      datatype: array of string elements
      description: |
        Types of credentials/grants to enable (enable only those that you want to use):
        - `password`: OAuth legacy password grant
        - `client_credentials`: OAuth client credentials grant
        - `authorization_code`: authorization code flow
        - `bearer`: JWT access token verification
        - `introspection`: OAuth introspection
        - `userinfo`: OpenID Connect user info endpoint authentication
        - `kong_oauth2`: Kong OAuth plugin issued tokens verification
        - `refresh_token`:  OAuth refresh token grant
        - `session`: session cookie authentication
    - name: anonymous
      required: false
      default:
      datatype: string
      description: |
        Let unauthenticated requests to pass, or skip the plugin if other authentication plugin
        has already authenticated the request by setting the value to anonymous Consumer.
    - group: Discovery
    - name: issuer
      required: true
      default:
      value_in_examples: <discovery_uri>
      datatype: string
      description: Discovery endpoint (or just the issuer identifier)
    - name: extra_jwks_uris
      required: false
      default:
      datatype: array of string elements
      description: JWKS uris whose public keys are trusted (in addition to keys found with discovery)
    - name: rediscovery_lifetime
      required: false
      default: 30
      datatype: integer
      description: How long to wait after doing a rediscovery, before doing it again
    - group: Endpoint Overrides
    - name: authorization_endpoint
      required: false
      default: "(discovered uri)"
      datatype: string
      description: The authorization endpoint
    - name: token_endpoint
      required: false
      default: "(discovered uri)"
      datatype: string
      description: The token endpoint
    - name: introspection_endpoint
      required: false
      default: "(discovered uri)"
      datatype: string
      description: The introspection endpoint
    - name: introspection_endpoint
      required: false
      default: "(discovered uri)"
      datatype: string
      description: The introspection endpoint
    - name: userinfo_endpoint
      required: false
      default: "(discovered uri)"
      datatype: string
      description: The user info endpoint
    - name: end_session_endpoint
      required: false
      default: "(discovered uri)"
      datatype: string
      description: The end session endpoint
    - name: token_exchange_endpoint
      required: false
      default: "(discovered uri)"
      datatype: string
      description: The token exchange endpoint
    - group: Endpoint Authentication
    - name: client_id
      required: false
      value_in_examples: [ "<client_id>" ]
      default: 
      datatype: array of string elements
      description: The client id for the plugin
    - name: client_secret
      required: false
      value_in_examples: [ "<client_secret>" ]
      default: 
      datatype: array of string elements
      description: The client secret for the plugin
    - name: client_auth
      required: false
      default: '(discovered or "client_secret_basic")'
      datatype: array of string elements
      description: |
        The authentication method used by the plugin when calling the endpoints:
        - `client_secret_basic`: send `client_id` and `client_secret` in `Authorization: Basic` header
        - `client_secret_post`: send `client_id` and `client_secret` as part of the body
        - `client_secret_jwt`: send client assertion signed with the `client_secret` as part of the body
        - `private_key_jwt`:  send client assertion signed with the `private key` as part of the body
        - `none`: do not authenticate
    - name: client_jwk
      required: false
      default: "(plugin managed)"
      datatype: array of records
      description: The JWK used for the `private_key_jwt` authentication
    - name: client_alg
      required: false
      default: '(client_secret_jwt: "HS256", private_key_jwt: "RS256")'
      datatype: array of string elements
      description: | 
        The algorithm to use for `client_secret_jwt` (only `HS*`) or `private_key_jwt` authentication:
        - `HS256`: HMAC using SHA-256
        - `HS384`: HMAC using SHA-384
        - `HS512`: HMAC using SHA-512
        - `RS256`: RSASSA-PKCS1-v1_5 using SHA-256
        - `RS512`: RSASSA-PKCS1-v1_5 using SHA-512
        - `ES256`: ECDSA using P-256 and SHA-256
        - `ES384`: ECDSA using P-384 and SHA-384
        - `ES512`: ECDSA using P-521 and SHA-512
        - `PS256`: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
        - `PS384`: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
        - `PS512`: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
        - `EdDSA`: EdDSA with Ed25519
    - name: client_arg
      required: false
      default:
      datatype: string
      description: The client to use for this request (selection is made with a request parameter)
    - group: Endpoint Authentication Overrides
    - name: token_endpoint_auth_method
      required: false
      default: "(see: client_auth)"
      datatype: string
      description: The token endpoint authentication method
    - name: introspection_endpoint_auth_method
      required: false
      default: "(see: client_auth)"
      datatype: string
      description: The introspection endpoint authentication method
    - name: revocation_endpoint_auth_method
      required: false
      default: "(see: client_auth)"
      datatype: string
      description: The revocation endpoint authentication method
    - group: Custom Endpoint Arguments      
    - name: response_mode
      required: false
      default: '"query"'
      datatype: string
      value_in_examples: form_post
      description: |
        The response mode passed to the authorization endpoint:
        - `query`: Instructs the identity provider to pass parameters in query string
        - `form_post`: Instructs the identity provider to pass parameters in request body
        - `fragment`: Instructs the identity provider to pass parameters in uri fragment (rarely useful as the plugin itself cannot read it)
    - name: response_type
      required: false
      default: [ "code" ]
      datatype: array of string elements
      description: The response type passed to the authorization endpoint
    - name: scopes
      required: false
      default: [ "openid" ]
      datatype: array of string elements
      description: The scopes passed to the authorization and token endpoints
    - name: audience
      required: false
      default: 
      datatype: array of string elements
      description: The audience passed to the authorization endpoint
    - name: redirect_uri
      required: false
      default: "(request uri)" 
      datatype: array of string elements
      description: The redirect uri passed to the authorization and token endpoints
    - name: discovery_headers_names
      required: false
      default: 
      datatype: array of string elements
      description: Extra header names passed to the discovery endpoint
    - name: discovery_headers_values
      required: false
      default: 
      datatype: array of string elements
      description: Extra header values passed to the discovery endpoint  
    - name: authorization_query_args_names
      required: false
      default: 
      datatype: array of string elements
      description: Extra query argument names passed to the authorization endpoint
    - name: authorization_query_args_values
      required: false
      default: 
      datatype: array of string elements
      description: Extra query argument values passed to the authorization endpoint 
    - name: authorization_query_args_client
      required: false
      default: 
      datatype: array of string elements
      description: Extra query arguments passed from the client to the authorization endpoint
    - name: token_headers_names
      required: false
      default: 
      datatype: array of string elements
      description: Extra header names passed to the token endpoint
    - name: token_headers_values
      required: false
      default: 
      datatype: array of string elements
      description: Extra header values passed to the token endpoint  
    - name: token_headers_client
      required: false
      default: 
      datatype: array of string elements
      description: Extra headers passed from the client to the token endpoint
    - name: token_post_args_names
      required: false
      default: 
      datatype: array of string elements
      description: Extra post argument names passed to the token endpoint
    - name: token_post_args_values
      required: false
      default: 
      datatype: array of string elements
      description: Extra post argument values passed to the token endpoint
    - name: token_post_args_client
      required: false
      default: 
      datatype: array of string elements
      description: Extra post arguments passed from the client to the token endpoint
    - name: introspection_hint  
      required: false
      default: '"access_token"'
      datatype: string
      description: Introspection hint parameter value passed to the introspection endpoint
    - name: introspection_headers_names
      required: false
      default: 
      datatype: array of string elements
      description: Extra header names passed to the introspection endpoint
    - name: introspection_headers_values
      required: false
      default: 
      datatype: array of string elements
      description: Extra header values passed to the introspection endpoint  
    - name: introspection_headers_client
      required: false
      default: 
      datatype: array of string elements
      description: Extra headers passed from the client to the introspection endpoint
    - name: introspection_post_args_names
      required: false
      default: 
      datatype: array of string elements
      description: Extra post argument names passed to the introspection endpoint
    - name: introspection_post_args_values
      required: false
      default: 
      datatype: array of string elements
      description: Extra post argument values passed to the introspection endpoint
    - name: introspection_post_args_client
      required: false
      default: 
      datatype: array of string elements
      description: Extra post arguments passed from the client to the introspection endpoint      
    - name: userinfo_headers_names
      required: false
      default: 
      datatype: array of string elements
      description: Extra header names passed to the user info endpoint
    - name: userinfo_headers_values
      required: false
      default: 
      datatype: array of string elements
      description: Extra header values passed to the user info endpoint  
    - name: userinfo_headers_client
      required: false
      default: 
      datatype: array of string elements
      description: Extra headers passed from the client to the user info endpoint
    - name: userinfo_query_args_names
      required: false
      default: 
      datatype: array of string elements
      description: Extra query argument names passed to the user info endpoint
    - name: userinfo_query_args_values
      required: false
      default: 
      datatype: array of string elements
      description: Extra query argument values passed to the user info endpoint
    - name: userinfo_query_args_client
      required: false
      default: 
      datatype: array of string elements
      description: Extra query arguments passed from the client to the user info endpoint
    - group: Parameter Types and Names
    - name: bearer_token_param_type
      required: false
      default: [ "header", "query", "body" ]
      datatype: array of string elements
      description: |
        Where to search the bearer token:
        - `header`: search from the headers
        - `query`: search from the query string
        - `body`: search from the body
        - `cookie`: search from the cookies
    - name: bearer_token_cookie_name
      required: false
      default: 
      datatype: string
      description: The cookie name in which the bearer token is passed
    - name: client_credentials_param_type
      required: false
      default: [ "header", "query", "body" ]
      datatype: array of string elements
      description: |
        Where to search the client credentials:
        - `header`: search from the headers
        - `query`: search from the query string
        - `body`: search from the body
    - name: password_param_type
      required: false
      default: [ "header", "query", "body" ]
      datatype: array of string elements
      description: |
        Where to search the username and password
        - `header`: search from the headers
        - `query`: search from the query string
        - `body`: search from the body
    - name: id_token_param_type
      required: false
      default: [ "header", "query", "body" ]
      datatype: array of string elements
      description: |
        Where to search the id token
        - `header`: search from the headers
        - `query`: search from the query string
        - `body`: search from the body
    - name: id_token_param_name
      required: false
      default: 
      datatype: string
      description: The name of the parameter used to pass the id token
    - name: refresh_token_param_type
      required: false
      default: [ "header", "query", "body" ]
      datatype: array of string elements
      description: |
        Where to search the refresh token
        - `header`: search from the headers
        - `query`: search from the query string
        - `body`: search from the body
    - name: refresh_token_param_name
      required: false
      default: 
      datatype: string
      description: The name of the parameter used to pass the refresh token
    - name: preserve_query_args
      required: false
      default: false
      datatype: boolean
      description: Preserve original query arguments over the authorization code flow redirections
    - name: run_on_preflight
      required: false
      default: true
      datatype: boolean
      description: Whether to run this plugin on pre-flight (`OPTIONS`) requests?
    - group: Authorization and Verification       
    - name: issuers_allowed
      required: false
      default: (discovered issuer)
      datatype: array of string elements
      description: The issuers allowed to be present in the tokens (`iss` claim)
    - name: scopes_required
      required: false
      default: (discovered issuer)
      datatype: array of string elements
      description: The scopes required to be in access token
    - name: scopes_claim
      required: false
      default: [ "scope" ]
      datatype: array of string elements
      description: The claim which contains the scopes
    - name: audience_required
      required: false
      default: 
      datatype: array of string elements
      description: The audience required to be in access token
    - name: audience_claim
      required: false
      default: [ "aud" ]
      datatype: array of string elements
      description: The claim which contains the audience
    - name: groups_required
      required: false
      default: 
      datatype: array of string elements
      description: The groups required to be in access token
    - name: groups_claim
      required: false
      default: [ "groups" ]
      datatype: array of string elements
      description: The claim which contains the groups    
    - name: roles_required
      required: false
      default: 
      datatype: array of string elements
      description: The roles required to be in access token
    - name: roles_claim
      required: false
      default: [ "groups" ]
      datatype: array of string elements
      description: The claim which contains the roles    
    - name: domains
      required: false
      default: 
      datatype: array of string elements
      description: The allowed values for the `hd` claim
    - name: max_age
      required: false
      default: 
      datatype: integer
      description: The maximum age (in seconds) compared to the `auth_time` claim
    - name: leeway
      required: false
      default: 0 
      datatype: integer
      description: Allow some leeway on the ttl / expiry verification
    - name: ignore_signature
      required: false
      default: 
      datatype: array of string elements
      description: |
        Skip the token signature verification on certain grants:      
        - `password`: OAuth password grant
        - `client_credentials`: OAuth client credentials grant
        - `authorization_code`: authorization code flow
        - `refresh_token`:  OAuth refresh token grant
        - `session`: session cookie authentication
        - `introspection`: OAuth introspection
        - `userinfo`: OpenID Connect user info endpoint authentication
    - name: reverify
      required: false
      default: false
      datatype: boolean
      description: Whether to verify tokens stored in the session?
    - name: refresh_tokens
      required: false
      default: true
      datatype: boolean
      description: Try to automatically refresh the expired access tokens?
    - name: introspect_jwt_tokens
      required: false
      default: false
      datatype: boolean
      description: Whether to introspect the JWT tokens (can be used to check for revocations)?
    - name: jwt_session_claim
      required: false
      default: '"sid"'
      datatype: string
      description: The claim to match against the JWT session cookie
    - name: jwt_session_cookie
      required: false
      default: 
      datatype: string
      description: The name of the JWT session cookie
    - name: verify_nonce
      required: false
      default: true
      datatype: boolean
      description: Verify nonce on authorization code flow?
    - name: verify_claims
      required: false
      default: true
      datatype: boolean
      description: Verify tokens for standard claims?
    - name: verify_signature
      required: false
      default: true
      datatype: boolean
      description: Verify signature of tokens?
    - name: verify_parameters
      required: false
      default: false
      datatype: boolean
      description: Verify plugin configuration against discovery?
    - group: Upstream and Downstream Headers
    - name: upstream_headers_claims
      required: false
      default: 
      datatype: array of string elements
      description: The upstream header claims
    - name: upstream_headers_names
      required: false
      default: 
      datatype: array of string elements
      description: The upstream header names for the claim values  
    - name: downstream_headers_claims
      required: false
      default: 
      datatype: array of string elements
      description: The downstream header claims
    - name: downstream_headers_names
      required: false
      default: 
      datatype: array of string elements
      description: The downstream header names for the claim values  



---
