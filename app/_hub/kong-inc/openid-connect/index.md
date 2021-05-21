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
  - [Microsoft Azure Active Directory][azure], [Active Directory Federation Services][adfs], and Live Connect
  - [Okta][okta]
  - [OneLogin][onelogin]
  - [OpenAM][openam]
  - [Paypal][paypal]
  - [PingFederate][pingfederate]
  - [Salesforce][salesforce]
  - [WSO2][wso2]
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
  [wso2]: https://is.docs.wso2.com/en/latest/learn/openid-connect/
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
  protocols: [ "http", "https", "grpc (depends on the grant)", "grpcs (depends on the grant)" ]
  dbless_compatible: yes
  config:
    - group: Authentication Grants
      description: enable only those that you want to use
    - name: auth_methods
      required: false
      default: [ "password", "client_credentials", "authorization_code", "bearer", "introspection", "userinfo", "kong_oauth2", "refresh_token", "session" ]
      value_in_examples: [ "authorization_code", "session" ]
      datatype: array of string elements
      description: |
        Types of credentials/grants to enable:
        - `password`: OAuth legacy password grant
        - `client_credentials`: OAuth client credentials grant
        - `authorization_code`: authorization code flow
        - `bearer`: JWT access token verification
        - `introspection`: OAuth introspection
        - `userinfo`: OpenID Connect user info endpoint authentication
        - `kong_oauth2`: Kong OAuth plugin issued tokens verification
        - `refresh_token`:  OAuth refresh token grant
        - `session`: session cookie authentication
    - group: Anonymous Access
      description: disabled by default
    - name: anonymous
      required: false
      default:
      datatype: uuid
      description: |
        Let unauthenticated requests to pass, or skip the plugin if other authentication plugin
        has already authenticated the request by setting the value to anonymous Consumer.
    - group: Discovery
      description: for auto-configuring most of the settings and providing the means of key rotation
    - name: issuer
      required: true
      default:
      value_in_examples: <discovery-uri>
      datatype: url
      description: The discovery endpoint (or just the issuer identifier)
    - name: rediscovery_lifetime
      required: false
      default: 30
      datatype: integer
      description: How long to wait after doing a discovery, before doing it again
    - group: Client
      description: that is used to interact with the identity provider
    - name: client_id
      required: false
      value_in_examples: [ "<client-id>" ]
      default: 
      datatype: array of string elements (the plugin supports multiple clients)
      description: The client id(s)
    - name: client_arg
      required: false
      default:
      datatype: string
      description: The client to use for this request (the selection is made with a request parameter with the same name)
    - group: Client Authentication
      description: how should the client authenticate with the identity provider          
    - name: client_auth
      required: false
      default: '(discovered or "client_secret_basic")'
      datatype: array of string elements (one for each client)
      description: |
        The authentication method used by the client (plugin) when calling the endpoints:
        - `client_secret_basic`: send `client_id` and `client_secret` in `Authorization: Basic` header
        - `client_secret_post`: send `client_id` and `client_secret` as part of the body
        - `client_secret_jwt`: send client assertion signed with the `client_secret` as part of the body
        - `private_key_jwt`:  send client assertion signed with the `private key` as part of the body
        - `none`: do not authenticate
    - name: client_secret
      required: false
      value_in_examples: [ "<client-secret>" ]
      default: 
      datatype: array of string elements (one for each client)
      description: The client secret(s)
    - name: client_jwk
      required: false
      default: "(plugin managed)"
      datatype: array of JWK records (one for each client)
      description: The JWK(s) used for the `private_key_jwt` authentication
    - name: client_alg
      required: false
      default: '(client_secret_jwt: "HS256", private_key_jwt: "RS256")'
      datatype: array of string elements (one for each client)
      description: | 
        The algorithm to use for `client_secret_jwt` (only `HS***`) or `private_key_jwt` authentication:
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
    - group: Endpoints
      description: normally not needed as the endpoints are discovered
    - name: authorization_endpoint
      required: false
      default: "(discovered uri)"
      datatype: url
      description: The authorization endpoint
    - name: token_endpoint
      required: false
      default: "(discovered uri)"
      datatype: url
      description: The token endpoint
    - name: introspection_endpoint
      required: false
      default: "(discovered uri)"
      datatype: url
      description: The introspection endpoint
    - name: revocation_endpoint
      required: false
      default: "(discovered uri)"
      datatype: url
      description: The revocation endpoint
    - name: userinfo_endpoint
      required: false
      default: "(discovered uri)"
      datatype: url
      description: The user info endpoint
    - name: end_session_endpoint
      required: false
      default: "(discovered uri)"
      datatype: url
      description: The end session endpoint
    - name: token_exchange_endpoint
      required: false
      default: "(discovered uri)"
      datatype: url
      description: The token exchange endpoint
    - group: Endpoint Authentication
      description: normally not needed as the client authentication can be specified for the client
    - name: token_endpoint_auth_method
      required: false
      default: "(see: client_auth)"
      datatype: string
      description: |
        The token endpoint authentication method:
        - `client_secret_basic`: send `client_id` and `client_secret` in `Authorization: Basic` header
        - `client_secret_post`: send `client_id` and `client_secret` as part of the body
        - `client_secret_jwt`: send client assertion signed with the `client_secret` as part of the body
        - `private_key_jwt`:  send client assertion signed with the `private key` as part of the body
        - `none`: do not authenticate        
    - name: introspection_endpoint_auth_method
      required: false
      default: "(see: client_auth)"
      datatype: string
      description: |
        The introspection endpoint authentication method:
        - `client_secret_basic`: send `client_id` and `client_secret` in `Authorization: Basic` header
        - `client_secret_post`: send `client_id` and `client_secret` as part of the body
        - `client_secret_jwt`: send client assertion signed with the `client_secret` as part of the body
        - `private_key_jwt`:  send client assertion signed with the `private key` as part of the body
        - `none`: do not authenticate        
    - name: revocation_endpoint_auth_method
      required: false
      default: "(see: client_auth)"
      datatype: string
      description: |
        The revocation endpoint authentication method:
        - `client_secret_basic`: send `client_id` and `client_secret` in `Authorization: Basic` header
        - `client_secret_post`: send `client_id` and `client_secret` as part of the body
        - `client_secret_jwt`: send client assertion signed with the `client_secret` as part of the body
        - `private_key_jwt`:  send client assertion signed with the `private key` as part of the body
        - `none`: do not authenticate
    - group: Discovery Endpoint Arguments
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
    - group: Authorization Endpoint Arguments
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
      datatype: array of urls (one for each client)
      description: The redirect uri passed to the authorization and token endpoints
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
    - group: Token Endpoint Arguments
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
    - group: Introspection Endpoint Arguments      
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
    - group: User Info Endpoint Arguments       
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
    - group: Bearer Token
      description: where to search for the bearer token
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
    - group: Client Credentials Grant
      description: where to search for the client credentials
    - name: client_credentials_param_type
      required: false
      default: [ "header", "query", "body" ]
      datatype: array of string elements
      description: |
        Where to search the client credentials:
        - `header`: search from the headers
        - `query`: search from the query string
        - `body`: search from the body
    - group: Password Grant
      description: where to search for the username and password
    - name: password_param_type
      required: false
      default: [ "header", "query", "body" ]
      datatype: array of string elements
      description: |
        Where to search the username and password
        - `header`: search from the headers
        - `query`: search from the query string
        - `body`: search from the body
    - group: Refresh Token Grant
      description: where to search for the refresh token (rarely used as the refresh tokens are in many cases bound to the client)
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
    - group: ID Token
      description: where to search for the id token (rarely send as part of the request)
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
    - group: Consumer Mapping
    - name: consumer_claim
      required: false
      default: 
      datatype: array of string elements
      description: The claim which is used for the consumer mapping
    - name: consumer_by
      required: false
      default: [ "username", "custom_id" ] 
      datatype: array of string elements
      description: |
        Consumer fields used for mapping:
        - `id`: try to find Consumer by `id`
        - `username`: try to find the matching Consumer by `username` 
        - `custom_id`: try to find the matching Consumer by `custom_id`
    - name: consumer_optional
      required: false
      default: false
      datatype: boolean
      description: Do not terminate the request, if consumer mapping fails?
    - group: Credential Mapping
    - name: credential_claim
      required: false
      default: [ "sub" ] 
      datatype: array of string elements
      description: The claim from which to derive a virtual credential (e.g. for rate-limiting plugin), in case the Consumer mapping is not used.
    - group: Issuer Verification       
    - name: issuers_allowed
      required: false
      default: (discovered issuer)
      datatype: array of string elements
      description: The issuers allowed to be present in the tokens (`iss` claim)
    - group: Authorization       
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
      default: [ "roles" ]
      datatype: array of string elements
      description: The claim which contains the roles
    - group: Claims Verification
    - name: verify_claims
      required: false
      default: true
      datatype: boolean
      description: Verify tokens for standard claims?
    - name: leeway
      required: false
      default: 0 
      datatype: integer
      description: Allow some leeway on the ttl / expiry verification      
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
    - group: Signature Verification
    - name: verify_signature
      required: false
      default: true
      datatype: boolean
      description: Verify signature of tokens?
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
    - name: extra_jwks_uris
      required: false
      default:
      datatype: array of string elements
      description: JWKS uris whose public keys are trusted (in addition to the keys found with the discovery)
    - group: Authorization Code Flow Verification
    - name: verify_nonce
      required: false
      default: true
      datatype: boolean
      description: Verify nonce on authorization code flow?
    - group: Configuration Verification
    - name: verify_parameters
      required: false
      default: false
      datatype: boolean
      description: Verify plugin configuration against discovery?
    - group: Upstream Headers
      description: the headers for the upstream service request
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
    - name: upstream_access_token_header  
      required: false
      default: authorization:bearer
      datatype: string
      description: The upstream access token header    
    - name: upstream_access_token_jwk_header  
      required: false
      default: 
      datatype: string
      description: The upstream access token jwk header
    - name: upstream_id_token_header  
      required: false
      default: 
      datatype: string
      description: The upstream id token header
    - name: upstream_id_token_jwk_header  
      required: false
      default: 
      datatype: string
      description: The upstream id token jwk header
    - name: upstream_refresh_token_header  
      required: false
      default: 
      datatype: string
      description: The upstream refresh token header
    - name: upstream_user_info_header
      required: false
      default: 
      datatype: string
      description: The upstream user info header
    - name: upstream_user_info_jwt_header
      required: false
      default: 
      datatype: string
      description: The upstream user info jwt header (in case the user info returns a JWT response)
    - name: upstream_introspection_header
      required: false
      default: 
      datatype: string
      description: The upstream introspection header
    - name: upstream_introspection_jwt_header
      required: false
      default: 
      datatype: string
      description: The upstream introspection header (in case the introspection returns a JWT response)
    - name: upstream_session_id_header
      required: false
      default: 
      datatype: string
      description: The upstream session id header
    - group: Downstream Headers 
      description: the headers for the downstream response
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
    - name: downstream_access_token_header  
      required: false
      default: authorization:bearer
      datatype: string
      description: The downstream access token header    
    - name: downstream_access_token_jwk_header  
      required: false
      default: 
      datatype: string
      description: The downstream access token jwk header
    - name: downstream_id_token_header  
      required: false
      default: 
      datatype: string
      description: The downstream id token header
    - name: downstream_id_token_jwk_header  
      required: false
      default: 
      datatype: string
      description: The downstream id token jwk header
    - name: downstream_refresh_token_header  
      required: false
      default: 
      datatype: string
      description: The downstream refresh token header
    - name: downstream_user_info_header
      required: false
      default: 
      datatype: string
      description: The downstream user info header
    - name: downstream_user_info_jwt_header
      required: false
      default: 
      datatype: string
      description: The downstream user info jwt header (in case the user info returns a JWT response)
    - name: downstream_introspection_header
      required: false
      default: 
      datatype: string
      description: The downstream introspection header
    - name: downstream_introspection_jwt_header
      required: false
      default: 
      datatype: string
      description: The downstream introspection header (in case the introspection returns a JWT response)
    - name: downstream_session_id_header
      required: false
      default: 
      datatype: string
      description: The downstream session id header
    - group: Cross-Origin Resource Sharing (CORS)
    - name: run_on_preflight
      required: false
      default: true
      datatype: boolean
      description: Whether to run this plugin on pre-flight (`OPTIONS`) requests?
    - group: HTTP Client
      description: generic settings for HTTP client when the plugin needs to interact with the identity provider
    - name: keepalive
      required: false
      default: true
      datatype: boolean
      description: Use keepalive with the HTTP client
    - name: ssl_verify
      required: false
      default: false
      datatype: boolean
      description: Verify identity provider server certificate
    - name: timeout
      required: false
      default: 10000
      datatype: integer
      description: Network IO timeout in milliseconds
    - name: http_version
      required: false
      default: 1.1
      datatype: number
      description: |
        The HTTP version used for the requests by this plugin:
        - `1.1`: HTTP 1.1 (the default)
        - `1.0`: HTTP 1.0
    - group: HTTP Client Proxy Settings
      description: only needed if the HTTP(S) requests to identity provider need to go through a proxy server
    - name: http_proxy
      required: false
      default: 
      datatype: url
      description: The HTTP proxy
    - name: http_proxy_authorization
      required: false
      default: 
      datatype: string
      description: The HTTP proxy authorization      
    - name: https_proxy
      required: false
      default: 
      datatype: url
      description: The HTTPS proxy
    - name: https_proxy_authorization
      required: false
      default: 
      datatype: string
      description: The HTTPS proxy authorization      
    - name: no_proxy
      required: false
      default: 
      datatype: array of string elements
      description: Do not use proxy with these hosts
    - group: Cache TTLs
    - name: cache_ttl
      required: false
      default: 3600
      datatype: integer
      description: The default cache ttl in seconds that is used in case the cached object does not specify the expiry
    - name: cache_ttl_max
      required: false
      default: 
      datatype: integer
      description: The maximum cache ttl in seconds (enforced)
    - name: cache_ttl_min
      required: false
      default: 
      datatype: integer
      description: The minimum cache ttl in seconds (enforced)
    - name: cache_ttl_neg
      required: false
      default: (derived from Kong configuration)
      datatype: integer
      description: The negative cache ttl in seconds
    - name: cache_ttl_resurrect
      required: false
      default: (derived from Kong configuration)
      datatype: integer
      description: The resurrection ttl in seconds
    - group: Cache Settings for the Endpoints
    - name: cache_tokens
      required: false
      default: true
      datatype: boolean
      description: Cache the token endpoint requests?
    - name: cache_tokens_salt
      required: false
      default: (auto generated)
      datatype: string
      description: |
        Salt used for generating the cache key that us used for caching the token
        endpoint requests. If you use multiple plugin instances of the OpenID Connect
        plugin and want to share token endpoint caches between the plugin
        instances, set the salt to the same value on each plugin.                      
    - name: cache_introspection
      required: false
      default: true
      datatype: boolean
      description: Cache the introspection endpoint requests?         
    - name: cache_token_exchange
      required: false
      default: true
      datatype: boolean
      description: Cache the token exchange endpoint requests?         
    - name: cache_user_info
      required: false
      default: true
      datatype: boolean
      description: Cache the user info requests?
    - group: Session Cookie
      description: used with the session cookie authentication 
    - name: session_cookie_name
      required: false
      default: '"session"'
      datatype: string
      description: The session cookie name                
    - name: session_cookie_lifetime
      required: false
      default: 3600
      datatype: integer
      description: The session cookie lifetime in seconds            
    - name: session_cookie_idletime
      required: false
      default: 
      datatype: integer
      description: The session cookie idle time in seconds            
    - name: session_cookie_renew
      required: false
      default: 600
      datatype: integer
      description: The session cookie renew time        
    - name: session_cookie_path
      required: false
      default: '"/"'
      datatype: string
      description: The session cookie Path flag
    - name: session_cookie_domain
      required: false
      default: 
      datatype: string
      description: The session cookie Domain flag
    - name: session_cookie_samesite
      required: false
      default: '"Lax"' 
      datatype: string
      description: |
        Controls whether a cookie is sent with cross-origin requests, providing some protection against cross-site request forgery attacks:
        - `Strict`: Cookies will only be sent in a first-party context and not be sent along with requests initiated by third party websites
        - `Lax`: Cookies are not sent on normal cross-site subrequests (for example to load images or frames into a third party site), but are sent when a user is navigating to the origin site (i.e. when following a link)
        - `None`: Cookies will be sent in all contexts, i.e in responses to both first-party and cross-origin requests. If SameSite=None is set, the cookie Secure attribute must also be set (or the cookie will be blocked)
        - `off`: do not set the Same-Site flag
    - name: session_cookie_httponly
      required: false
      default: true
      datatype: boolean
      description: Forbids JavaScript from accessing the cookie, for example, through the Document.cookie property.
    - name: session_cookie_secure
      required: false
      default: (from the request scheme)
      datatype: boolean
      description: |
        Cookie is only sent to the server when a request is made with the https: scheme (except on localhost),
        and therefore is more resistant to man-in-the-middle attacks.
    - name: session_cookie_maxsize
      required: false
      default: 4000
      datatype: integer
      description: The maximum size of each cookie chunk in bytes
    - group: Authorization Cookie
      description: used during authorization code flow for verification and preserving the settings
    - name: authorization_cookie_name
      required: false
      default: '"authorization"'
      datatype: string
      description: The authorization cookie name                
    - name: authorization_cookie_lifetime
      required: false
      default: 600
      datatype: integer
      description: The authorization cookie lifetime in seconds            
    - name: authorization_cookie_path
      required: false
      default: '"/"'
      datatype: string
      description: The authorization cookie Path flag
    - name: authorization_cookie_domain
      required: false
      default: 
      datatype: string
      description: The authorization cookie Domain flag
    - name: authorization_cookie_samesite
      required: false
      default: '"off"'
      datatype: string
      description: |
        Controls whether a cookie is sent with cross-origin requests, providing some protection against cross-site request forgery attacks:
        - `Strict`: Cookies will only be sent in a first-party context and not be sent along with requests initiated by third party websites
        - `Lax`: Cookies are not sent on normal cross-site subrequests (for example to load images or frames into a third party site), but are sent when a user is navigating to the origin site (i.e. when following a link)
        - `None`: Cookies will be sent in all contexts, i.e in responses to both first-party and cross-origin requests. If SameSite=None is set, the cookie Secure attribute must also be set (or the cookie will be blocked)
        - `off`: do not set the Same-Site flag
    - name: authorization_cookie_httponly
      required: false
      default: true
      datatype: boolean
      description: Forbids JavaScript from accessing the cookie, for example, through the Document.cookie property.
    - name: authorization_cookie_secure
      required: false
      default: (from the request scheme)
      datatype: boolean
      description: |
        Cookie is only sent to the server when a request is made with the https: scheme (except on localhost),
        and therefore is more resistant to man-in-the-middle attacks.
    - group: Session Settings
    - name: session_secret
      required: false
      default: (with database, or traditional mode, the value is auto-generated and stored along the issuer discovery information in the database)
      datatype: string
      value_in_examples: <session-secret>
      description: The session secret
    - name: session_strategy
      required: false
      default: '"default"'
      datatype: string
      description: |
        The session strategy:
        - `default`:  reuses session identifiers over modifications (but can be problematic with single-page applications with a lot of concurrent asynchronous requests)
        - `regenerate`: generates a new session identifier on each modification and does not use expiry for signature verification (useful in single-page applications or SPAs)
    - name: session_compressor
      required: false
      default: '"default"'
      datatype: string
      description: |
        The session strategy:
        - `none`: no compression
        - `zlib`: use zlib to compress cookie data
    - name: session_storage
      required: false
      default: '"cookie"'
      datatype: string
      description: |
        The session storage for session data:
        - `cookie`: stores session data with the session cookie (the session cannot be invalidated or revoked without changing session secret, but is stateless, and doesn't require a database)
        - `memcache`: stores session data in memcached
        - `redis`: stores session data in Redis
    - name: reverify
      required: false
      default: false
      datatype: boolean
      description: Whether to always verify tokens stored in the session?                  
    - group: Session Settings for Memcached
    - name: session_memcache_prefix
      required: false
      default: '"sessions"'
      datatype: string
      description: The memcached session key prefix
    - name: session_memcache_socket
      required: false
      default: 
      datatype: string
      description: The memcached unix socket path
    - name: session_memcache_host
      required: false
      default: '"127.0.0.1"'
      datatype: string
      description: The memcached host
    - name: session_memcache_port
      required: false
      default: 11211
      datatype: integer
      description: The memcached port
    - group: Session Settings for Redis
    - name: session_redis_prefix
      required: false
      default: '"sessions"'
      datatype: string
      description: The Redis session key prefix
    - name: session_redis_socket
      required: false
      default: 
      datatype: string
      description: The Redis unix socket path
    - name: session_redis_host
      required: false
      default: '"127.0.0.1"'
      datatype: string
      description: The Redis host
    - name: session_redis_port
      required: false
      default: 6379
      datatype: integer
      description: The Redis port
    - name: session_redis_auth
      required: false
      default: (from kong)
      datatype: string
      description: The Redis password
    - name: session_redis_connect_timeout
      required: false
      default: (from kong)
      datatype: integer
      description: The Redis connection timeout in milliseconds
    - name: session_redis_read_timeout
      required: false
      default: (from kong)
      datatype: integer
      description: The Redis read timeout in milliseconds
    - name: session_redis_send_timeout
      required: false
      default: (from kong)
      datatype: integer
      description: The Redis send timeout in milliseconds
    - name: session_redis_ssl
      required: false
      default: false
      datatype: boolean
      description: Use SSL/TLS for Redis connection
    - name: session_redis_ssl_verify
      required: false
      default: false
      datatype: boolean
      description: Verify Redis server certificate?
    - name: session_redis_server_name
      required: false
      default: 
      datatype: string
      description: The SNI used for connecting the Redis server
    - name: session_redis_cluster_nodes
      required: false
      default: 
      datatype: array of host records
      description: The Redis cluster nodes
    - name: session_redis_cluster_maxredirections
      required: false
      default: 
      datatype: integer
      description: The Redis cluster maximum redirects
    - group: Login
      description: what action the plugin takes after a successful login
    - group: Logout
      description: how to trigger logout with plugin
    - group: Miscellaneous      
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
    - name: preserve_query_args
      required: false
      default: false
      datatype: boolean
      description: Preserve original query arguments over the authorization code flow redirections      
---
