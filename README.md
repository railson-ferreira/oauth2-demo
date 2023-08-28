# OAuth 2 Demo

A demo implementation of OAuth 2 (Sign in with Google)

### Endpoints:

- / [GET]
- /healthcheck [GET]
- /google/sign-in [GET, POST]
- /google/callback [GET] params: {code: string}
- /tokensignin [POST] params: {idToken: string}
- /me [GET] 🔒