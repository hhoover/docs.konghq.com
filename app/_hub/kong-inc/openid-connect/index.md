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

  The plugin has been tested with several OpenID Connect capable providers, such as:

  - [Auth0][auth0]
  - [Amazon AWS Cognito][cognito]
  - [Connect2id][connect2id]
  - [Dex][dex]
  - [Gluu][gluu]
  - [Google][google]
  - [IdentityServer4][identityserver4]
  - [Keycloak][keycloak]
  - [Microsoft Azure Active Directory v1][azurev1]
  - [Microsoft Azure Active Directory v2][azurev2]
  - Microsoft Live Connect
  - [Okta][okta]
  - [OneLogin][onelogin]
  - [OpenAM][openam]
  - [Paypal][paypal]
  - [PingFederate][pingfederate]
  - [Salesforce][salesforce]
  - [Yahoo!][yahoo]

  As long as your provider supports OpenID Connect standards, the plugin should
  work, even if it is not specifically tested against it. Let Kong know if you
  want your provider to be tested and added to the list.

  [connect]: http://openid.net/specs/openid-connect-core-1_0.html
  [oauth2]: https://tools.ietf.org/html/rfc6749
  [jwt]: https://tools.ietf.org/html/rfc7519
  [jws]: https://tools.ietf.org/html/rfc7515
  [auth0]: https://auth0.com/docs/protocols/oidc
  [cognito]: https://aws.amazon.com/cognito/
  [connect2id]: https://connect2id.com/products/server
  [dex]: https://github.com/coreos/dex/blob/master/Documentation/openid-connect.md
  [gluu]: https://gluu.org/docs/ce/api-guide/openid-connect-api/
  [google]: https://developers.google.com/identity/protocols/OpenIDConnect
  [identityserver4]: https://identityserver4.readthedocs.io/
  [keycloak]: http://www.keycloak.org/documentation.html
  [azurev1]: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code
  [azurev2]: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols-oidc
  [okta]: https://developer.okta.com/docs/api/resources/oidc.html
  [onelogin]: https://developers.onelogin.com/openid-connect
  [openam]: https://backstage.forgerock.com/docs/openam/13.5/admin-guide/#chap-openid-connect
  [paypal]: https://developer.paypal.com/docs/integration/direct/identity/log-in-with-paypal/
  [pingfederate]: https://documentation.pingidentity.com/pingfederate/
  [salesforce]: https://developer.salesforce.com/page/Inside_OpenID_Connect_on_Force.com
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
  protocols: ["http", "https"]
  dbless_compatible: yes
  config:
    - name: auth_methods
      required: false
      default: |
        ["`password`", "`client_credentials`", "`authorization_code`", "`bearer`", "`introspection`", "`userinfo`", "`kong_oauth2`", "`refresh_token`", "`session`"]
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
        has already authenticated the request by setting the value to anonymous Consumer id.
    - name: issuer
      required: true
      default:
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
    - name: authorization_endpoint
      required: false
      default: (discovered uri)
      datatype: string
      description: The authorization endpoint
    - name: token_endpoint
      required: false
      default: (discovered uri)
      datatype: string
      description: The token endpoint
    - name: introspection_endpoint
      required: false
      default: (discovered uri)
      datatype: string
      description: The introspection endpoint
    - name: introspection_endpoint
      required: false
      default: (discovered uri)
      datatype: string
      description: The introspection endpoint
    - name: userinfo_endpoint
      required: false
      default: (discovered uri)
      datatype: string
      description: The user info endpoint
    - name: end_session_endpoint
      required: false
      default: (discovered uri)
      datatype: string
      description: The end session endpoint
    - name: token_exchange_endpoint
      required: false
      default: (discovered uri)
      datatype: string
      description: The token exchange endpoint
    - name: client_id
      required: false
      default: 
      datatype: array of string elements
      description: The client id for the plugin
    - name: client_secret
      required: false
      default: 
      datatype: array of string elements
      description: The client secret for the plugin
    - name: client_auth
      required: false
      default: (discovered or `client_secret_basic`)
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
      default: (plugin managed)
      datatype: array of records
      description: The JWK used for `private_key_jwt` authentication.
    - name: client_alg
      required: false
      default: (for `client_secret_jwt`: `HS256`, for `private_key_jwt`: `RS256`)
      datatype: array of string elements
      description: | 
        The algorithm to use for `client_secret_jwt` or `private_key_jwt` authentication:
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
    - name: token_endpoint_auth_method
      required: false
      default: (see `client_auth`)
      datatype: string
      description: The token endpoint authentication method
    - name: introspection_endpoint_auth_method
      required: false
      default: (see `client_auth`)
      datatype: string
      description: The introspection endpoint authentication method
    - name: revocation_endpoint_auth_method
      required: false
      default: (see `client_auth`)
      datatype: string
      description: The revocation endpoint authentication method
    - name: response_mode
      required: false
      default: "`query`"
      datatype: string
      description: The response mode passed to authorization endpoint
    - name: response_type
      required: false
      default: |
        ["`code`"]
      datatype: array of string elements
      description: The response type passed to authorization endpoint
    - name scopes
      required: false
      default: | 
        ["`openid`"]
      datatype: array of string elements
      description: The scopes passed to authorization and token endpoints
    - name audience
      required: false
      default: 
      datatype: array of string elements
      description: The audience passed to authorization endpoint
    - name: redirect_uri
      default: (request uri) 
      datatype: array of string elements
      description: The redirect uri passed to authorization and token endpoints
      
---
