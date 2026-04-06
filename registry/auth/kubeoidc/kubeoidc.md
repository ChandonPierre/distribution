# kubeoidc Auth Provider

## Overview

`kubeoidc` is a new authentication provider for the Distribution registry that enables Kubernetes workloads to authenticate using their native [service account tokens](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens). It also includes a built-in token exchange endpoint so that standard Docker clients — `docker login`, `imagePullSecrets`, and the kubelet — work without any external token server.

The feature consists of five components:

| File | Responsibility |
|---|---|
| `accesscontroller.go` | Provider registration, config, `Authorized()`, registry-issued JWT validation, catalog prefix probe |
| `oidc.go` | OIDC discovery, per-issuer JWKS cache, HTTP client |
| `policy.go` | CEL policy compilation, evaluation, live file reload |
| `tokenendpoint.go` | Built-in `/auth/token` HTTP handler, registry JWT issuance |
| `*_test.go` | 30+ unit and integration tests |

Additional changes outside this package:

- `registry/auth/auth.go` — new `TokenEndpointer` optional interface; `CatalogPrefixes` field on `Grant`
- `registry/handlers/app.go` — auto-registers the token endpoint; threads `CatalogPrefixes` into request context
- `registry/handlers/context.go` — `withCatalogPrefixes` / `getCatalogPrefixes` context helpers
- `registry/handlers/catalog.go` — post-fetch prefix filter on `/v2/_catalog` responses

---

## Problem Statement

### Why a new provider?

The existing `token` auth provider requires an **external** authorization server. The registry redirects unauthenticated clients to that server, which performs its own authentication (username/password, LDAP, etc.) and issues a scoped JWT. The registry then verifies that JWT locally.

This model works for human users but is awkward in Kubernetes:

1. Kubernetes already provides cryptographically signed service account (SA) tokens via the `serviceAccountToken` projected volume. Every pod has one.
2. Running a separate token server solely to exchange SA tokens for registry tokens adds operational complexity, an extra network hop, and another service to secure and scale.
3. SA tokens are OIDC-compatible: the cluster exposes a standard OIDC discovery endpoint and JWKS, so any party can verify them independently.

`kubeoidc` validates SA tokens directly against the cluster's OIDC endpoint — no external token server required.

### Why not the existing `token` provider with an SA-validating backend?

The existing `token` provider assumes the external server performs authentication; the registry's role is only to verify the resulting JWT. Plugging SA token validation into that server would still require operating a separate service, since the JWT would not contain the expected `accessSet` claims. `kubeoidc` moves the validation into the registry process itself.

---

## Architecture

```
Kubernetes Pod
  │
  │  (1) POST /auth/token  Basic user:<SA token>
  ▼
Distribution Registry  ──────────────────────────────────┐
  │                                                        │
  │  kubeoidc                                              │
  │  ┌─────────────────────────────────────────────────┐  │
  │  │ tokenEndpointHandler.ServeHTTP()                 │  │
  │  │   • parse scope query params                     │  │
  │  │   • extract Basic auth → SA token (password)    │  │
  │  │   • validate SA token via OIDC/JWKS              │  │
  │  │   • evaluate CEL access policies                 │  │
  │  │   • issue scoped registry JWT (ES256)            │  │
  │  └─────────────────────────────────────────────────┘  │
  │                                                        │
  │  (2) GET /v2/myrepo/tags/list                          │
  │      Authorization: Bearer <registry JWT>              │
  │  ┌─────────────────────────────────────────────────┐  │
  │  │ accessController.Authorized()                    │  │
  │  │   • parse JWT                                    │  │
  │  │   • iss == tokenIssuer → verify with local key   │  │
  │  │   • check embedded access claims                 │  │
  │  └─────────────────────────────────────────────────┘  │
  └────────────────────────────────────────────────────────┘
         │
         │ (OIDC discovery + JWKS fetch, done once per issuer)
         ▼
   Kubernetes API Server
   /.well-known/openid-configuration
   /openid/v1/jwks
```

---

## Component Design

### OIDC Discovery and JWKS Cache (`oidc.go`)

#### Why lazy initialization?

JWKS caches are not pre-populated at startup. The first request carrying a token from a given issuer triggers discovery and an initial JWKS fetch. This design:

- Avoids blocking registry startup on remote OIDC endpoints (which may be temporarily unavailable).
- Naturally handles multi-cluster configurations — only clusters that actually send tokens pay the discovery cost.

Double-checked locking (`sync.RWMutex` + map check inside write lock) ensures exactly one goroutine initializes each cache even under concurrent load.

#### Stale-while-revalidate refresh model

`getKeys()` never blocks the calling request. When the cache is stale (age > `jwks_refresh_interval`, default 1 hour), a background goroutine is launched to refresh it. The caller receives the current (potentially stale) key set immediately.

A `refreshing` boolean prevents goroutine storms when many requests arrive simultaneously with a stale cache.

`syncRefresh()` is reserved for the specific case where a token presents a key ID (`kid`) not present in the current JWKS — an indication that the cluster has rotated its signing key. In this case, one synchronous re-fetch is attempted before rejecting the token.

#### Trusted issuers allowlist

The trusted issuer check is performed before any network call. An unknown issuer is rejected immediately. This prevents:
- Accidental SSRF via attacker-controlled `iss` claims
- OIDC discovery requests to arbitrary URLs

Entries in `issuers` may be exact URLs or prefix patterns ending in `*`:

```yaml
issuers:
  - https://kubernetes.default.svc                 # exact
  - https://oidc.example.com/id/*                  # matches any tenant under this path
```

Prefix patterns are stored without the trailing `*` and matched with `strings.HasPrefix`. Each matching issuer URL still gets its own JWKS cache — discovery is done per concrete issuer, not per pattern.

### CEL Policy Engine (`policy.go`)

#### Why CEL?

Kubernetes SA tokens carry a `sub` claim of the form `system:serviceaccount:<namespace>:<name>` and a `kubernetes.io/serviceaccount/namespace` claim. There is no standardized claim for "which repositories this workload may access." Access decisions therefore require a programmable expression language.

[CEL (Common Expression Language)](https://github.com/google/cel-spec) was chosen because:
- It is the same language used by Kubernetes admission webhooks, Envoy RBAC, and the Kubernetes gateway API — operators are already familiar with it.
- Expressions are compiled once at startup (type-checked and bytecode-compiled), making per-request evaluation microseconds-fast.
- It is sandboxed (no I/O, no loops), making it safe for operator-supplied expressions.
- `github.com/google/cel-go` is the canonical Go implementation, maintained by Google.

#### CEL variable model

Both `token` and `request` are exposed as `map[string]any` (CEL type: `map(string, dyn)`). This was deliberately chosen over a typed struct approach:

- The full JWT payload is passed as `token` — not just `iss/sub/aud` — so policies can access any claim, including Kubernetes-specific ones like `kubernetes.io/serviceaccount/namespace`.
- New JWT claims require no code changes, only policy updates.
- CEL's dynamic type handles the heterogeneous claim values naturally.

The `aud` claim is normalised from `string | []interface{}` to `[]string` before CEL evaluation (`toStringSlice()`), because the JWT spec allows both forms and CEL list operations require a consistent type.

#### Policy evaluation semantics

Policies are evaluated in declaration order. The first policy that evaluates to `true` grants access for that specific `(type, repository, action)` tuple. A policy evaluation error (e.g., type mismatch in the expression) is non-fatal: it logs a warning and evaluation continues to the next policy.

For multi-access requests (e.g., a push that requires both `pull` and `push`), each access item is evaluated independently. All items must be granted; if any is denied, `ErrInsufficientScope` is returned.

#### Catalog prefix filtering

Each policy may optionally carry a `catalog_prefix`, `catalog_prefix_expression`, or `catalog_full_access` field. When present, the policy participates in `/v2/_catalog` multi-tenancy filtering:

1. At token issuance, `catalogPrefixesForToken` iterates over policies that declare one of these fields and resolves the catalog access for this specific token (see below).
2. The union of resolved prefixes is embedded in the registry JWT as the `catalog_prefixes` claim (omitted when empty, to keep tokens compact). A `catalog_full_access` match omits the claim entirely, signalling unrestricted access.
3. When `Authorized()` validates a registry-issued token for a catalog request, it propagates `catalog_prefixes` from the JWT into `auth.Grant.CatalogPrefixes`.
4. `GetCatalog` filters the repository list in memory, keeping only names that start with at least one of the granted prefixes. A nil `CatalogPrefixes` means no filtering.

**Three resolution strategies:**

`catalog_full_access` (for admin/operator policies) — if `true` and the main policy expression matches, prefix filtering is bypassed entirely. The token carries no `catalog_prefixes` claim and the caller sees every repository in the registry. Takes precedence over the prefix strategies.

```yaml
- name: registry-admins
  expression: |
    token["sub"].startsWith("system:serviceaccount:registry-admin:")
  catalog_full_access: true
```

`catalog_prefix_expression` (preferred for multi-tenant deployments) — a CEL expression evaluated against the token map that must return a non-empty string. The result is used directly as the prefix. This is the right choice when the tenant identifier lives in a JWT claim:

```yaml
# request["repository"].startsWith(token["kubernetes.io/namespace"]) in the
# main expression; derive the same prefix from the token for catalog filtering.
catalog_prefix_expression: 'token["kubernetes.io/serviceaccount/namespace"]'
```

`catalog_prefix` (static) — a fixed string. The main policy expression is probed with `request["repository"] = <prefix>` at token issuance; if the expression grants pull access, the prefix is included. Suitable when the prefix is known ahead of time and baked into the expression:

```yaml
catalog_prefix: cw4637/
```

A `nil` `CatalogPrefixes` value means no filtering (all repositories visible). This applies to:
- Tokens issued to callers matching a `catalog_full_access: true` policy.
- Direct SA token requests (the `Authorized()` OIDC path — a v1 limitation; these callers do not go through the token endpoint where prefix resolution occurs).
- Non-kubeoidc deployments (`token`, `htpasswd`, etc.).

A non-nil empty slice means the caller was issued a catalog-scoped token but no prefixes resolved, so the catalog response is empty.

#### Live policy reload

When `policy_file` is configured, a background goroutine polls the file every `policy_reload_interval` (default 30s). It computes a SHA-256 hash of the file contents to avoid unnecessary recompilation. On a detected change:

1. The file is parsed and all expressions compiled.
2. If compilation succeeds, `atomic.Pointer[policySet].Store()` atomically replaces the active policy set. In-flight requests complete with the previous set; new requests see the new set immediately. No lock contention.
3. If compilation fails, the error is logged and the previous policy set remains active. The registry never enters a state where all policies are broken due to a bad config push.

### Built-in Token Endpoint (`tokenendpoint.go`)

#### The Docker Bearer auth flow

Docker clients (CLI, kubelet, containerd) implement the [Docker Registry Token Authentication](https://distribution.github.io/distribution/spec/auth/token/) specification:

1. Client sends an unauthenticated request to `/v2/...`
2. Registry responds `401 WWW-Authenticate: Bearer realm="https://registry/auth/token",service="registry.example.com",scope="repository:myrepo:pull"`
3. Client fetches `GET /auth/token?service=...&scope=...` with credentials
4. Registry returns a signed JWT; client presents it as `Authorization: Bearer <jwt>` on subsequent requests

SA tokens do not implement this flow natively — they are issued by the cluster, not the registry. The built-in token endpoint bridges the two worlds: it accepts an SA token as the Basic auth password, validates it, and issues a scoped registry JWT.

#### Anonymous token requests and public access

The token endpoint supports unauthenticated (anonymous) requests to enable policy-based public access. When a client sends a token request with no `Authorization` header, the endpoint evaluates CEL policies with a nil token map. Policies that do not reference `token` at all (e.g. a blanket public-pull rule) can still match:

```yaml
- name: public-pull
  expression: |
    request["type"] == "repository" &&
    request["repository"].startsWith("public/") &&
    request["actions"] == ["pull"]
```

If at least one scope is granted, a valid registry JWT is issued and returned. If no policies grant access to any requested scope, the endpoint returns `401` with a `WWW-Authenticate: Basic` challenge so that clients carrying credentials retry with them. This ensures clients with valid SA tokens are not silently handed a zero-access token.

**Credential edge cases handled by the token endpoint:**

| Condition | Behaviour |
|---|---|
| No `Authorization` header | Anonymous path; policies evaluated with nil token. Returns 401 if nothing is granted. |
| Malformed `Authorization` header (not valid Basic) | `401 invalid credentials` |
| Valid Basic auth with empty password | `401` with `WWW-Authenticate: Basic` — signals stale/expired imagePullSecret to re-authenticate rather than falling through to anonymous |
| Valid Basic auth with non-empty password | SA token path; OIDC/JWKS validation runs |

#### Why the registry issues its own JWT rather than reusing the SA token

The most obvious alternative would be to pass the SA token directly as the Bearer token on step 4 above and have `Authorized()` validate it via OIDC/JWKS on every request. This was rejected for several reasons:

1. **The Docker spec requires an `access` claim.** Distribution's `Authorized()` is called once per API request; for SA tokens, there is no `access` claim to check. The registry would have to re-run CEL policies on every blob GET, manifest GET, etc.

2. **Latency.** OIDC/JWKS validation involves a cache lookup and potentially a network round-trip (on cache miss or key rotation). Doing this on every registry operation adds latency to what are often tight loops in CI pipelines (layer push, manifest PUT, etc.).

3. **SA token lifetime.** SA tokens can have lifetimes of hours. A registry JWT is scoped to a specific set of repositories and actions, expires in minutes (default 5 minutes), and cannot be used for anything other than the registry. This is a meaningful security improvement: even if a registry JWT is intercepted, its blast radius is limited.

4. **Compatibility.** Docker clients, `imagePullSecrets`, and the kubelet all expect a short-lived opaque bearer token from the token endpoint. Returning the SA token directly would require those clients to understand SA token semantics.

#### Two-path `Authorized()`

`Authorized()` detects which kind of token it received by reading the `iss` claim before signature verification:

- `iss == tokenIssuer` (default: value of `service`): **registry-issued token** → verified with the local ECDSA public key, access checked against the embedded `access` claim.
- Any other `iss`: **SA token** → verified via OIDC/JWKS, access checked via CEL policies.

This separation means the OIDC/JWKS path is only exercised at token exchange time (step 3 above), not on every subsequent API call.

#### Signing key

The token endpoint signs registry JWTs with an ECDSA P-256 key (`ES256`). This can be:

- **Configured** (`signing_key: /path/to/key.pem`): a PEM-encoded EC private key (SEC 1 format) or PKCS#8 key. Use this in production or when running multiple registry replicas (all replicas must share the same key so tokens issued by one replica are accepted by another).
- **Ephemeral** (no `signing_key`): an ECDSA P-256 key pair is generated at startup. A warning is logged. Tokens are invalidated on restart and cannot be verified across replicas.

The current key pair is stored in `accessController.signingKey` as an `atomic.Pointer[signingKeyState]` shared with `tokenEndpointHandler`. Both signing (token issuance) and verification (`authorizeRegistryToken`) always read from this atomic, so they stay in sync.

#### Signing key hot reload

When `signing_key` is configured, a background goroutine polls the file every `policy_reload_interval` (default 30s) using the same SHA-256 change-detection pattern as the policy reloader. On a detected change, a new `signingKeyState` (private key + public key) is atomically stored. In-flight token verifications complete with the previous key; new issuances use the new key immediately.

On error (unreadable file, invalid PEM, wrong curve), a warning is logged and the previous key remains active.

This enables short-lived certificates to be used as the signing key — the registry picks up rotations without a restart. Note that tokens already issued before a rotation will fail verification once the key is replaced. Keep `token_expiry` short (≤ 2m) to bound the impact window, or retain the previous public key for verification (not currently implemented).

A note on `REGISTRY_HTTP_SECRET`: that environment variable is used to sign state cookies for the OAuth2 flow — it is not used for JWT signing and serves a different purpose.

### `TokenEndpointer` Interface (`registry/auth/auth.go`)

```go
type TokenEndpointer interface {
    TokenHandler() http.Handler
}
```

This optional interface allows any access controller to expose a built-in token endpoint. `registry/handlers/app.go` checks for this interface after constructing the access controller and, if present, registers the handler on the root router at `/auth/token`:

```go
if te, ok := accessController.(auth.TokenEndpointer); ok {
    app.router.Path("/auth/token").Handler(te.TokenHandler())
    dcontext.GetLogger(app).Infof("registered built-in token endpoint at /auth/token")
}
```

No existing code was changed to accommodate this — it is a pure addition using Go's implicit interface satisfaction. The `token` provider and `htpasswd` provider are unaffected.

---

## Configuration Reference

```yaml
auth:
  kubeoidc:
    # Required
    realm: https://registry.example.com/auth/token  # Token endpoint URL (returned in WWW-Authenticate)
    issuers:                                          # Trusted OIDC issuer URLs (from JWT `iss`)
      - https://kubernetes.default.svc               # exact match
      - https://oidc.example.com/id/*                # prefix match — trusts any tenant under this path

    # Optional
    service: registry.example.com    # Expected JWT `aud` value; if omitted, aud check is skipped
    insecure_skip_tls_verify: false  # Skip TLS cert verification for OIDC/JWKS endpoints
    jwks_refresh_interval: 1h        # How often to refresh JWKS in background (default: 1h)

    # Token endpoint
    signing_key: /etc/registry/token-signing.pem  # PEM ECDSA private key; omit for ephemeral; hot-reloaded on change
    token_expiry: 5m                               # Registry JWT lifetime (default: 5m)
    token_issuer: registry.example.com             # `iss` in registry JWTs (default: service)

    # Inline policies (used when policy_file is not set)
    policies:
      - name: ci-builders-push
        expression: |
          token["sub"].startsWith("system:serviceaccount:ci:") &&
          request["type"] == "repository" &&
          "push" in request["actions"]

      # Dynamic catalog prefix: tenant namespace comes from the SA token itself.
      # A single policy covers all tenants; the catalog is scoped per-caller.
      - name: tenant-pull
        expression: |
          token["iss"].startsWith("https://oidc.example.com/id/") &&
          request["type"] == "repository" &&
          request["repository"].startsWith(token["kubernetes.io/serviceaccount/namespace"] + "/") &&
          "pull" in request["actions"]
        catalog_prefix_expression: 'token["kubernetes.io/serviceaccount/namespace"] + "/"'

      # Static catalog prefix: prefix is fixed and known at policy-write time.
      - name: tenant-a-pull
        expression: |
          token["iss"].startsWith("https://oidc.example.com/id/tenant-a") &&
          request["type"] == "repository" &&
          request["repository"].startsWith("tenant-a/") &&
          "pull" in request["actions"]
        catalog_prefix: tenant-a/

      # Full catalog access: registry admins see every repository.
      - name: registry-admins
        expression: |
          token["sub"].startsWith("system:serviceaccount:registry-admin:")
        catalog_full_access: true

    # OR: external policy file with live reload
    policy_file: /etc/registry/policies.yaml
    policy_reload_interval: 30s
```

### CEL Variables

| Variable | Type | Description |
|---|---|---|
| `token` | `map(string, dyn)` | Full JWT payload (all claims). Common keys: `iss`, `sub`, `aud` (always `[]string`), `exp`, `iat`, `kubernetes.io/serviceaccount/namespace`, etc. |
| `request` | `map(string, dyn)` | Access request. Keys: `type` (string), `repository` (string), `actions` (list of strings) |

`service` is optional. When omitted, the JWT audience check is skipped entirely and CEL policies are solely responsible for determining access. This is useful when tokens from multiple issuers use different `aud` values (e.g., EKS tokens use `sts.amazonaws.com`).

### Policy Fields

| Field | Required | Description |
|---|---|---|
| `name` | yes | Human-readable identifier (appears in log warnings on eval errors) |
| `expression` | yes | CEL boolean expression; `true` = access granted |
| `catalog_prefix` | no | Static repository name prefix for `/v2/_catalog` filtering. The main expression is probed with `request["repository"] = <prefix>` at token issuance; if granted, the prefix is embedded in `catalog_prefixes`. |
| `catalog_prefix_expression` | no | CEL expression evaluated against the token map; must return a non-empty string used as the catalog prefix. Takes precedence over `catalog_prefix` when both are set. Use this when the tenant/org identifier is a JWT claim. |
| `catalog_full_access` | no | If `true`, any token that satisfies the main policy expression receives an unrestricted `/v2/_catalog` view (no prefix filtering). The issued JWT carries no `catalog_prefixes` claim, so the catalog handler returns all repositories. Takes precedence over `catalog_prefix` and `catalog_prefix_expression`. Use this for admin or operator policies that need a global view of the registry. |

---

## Security Considerations

### Token forgery

SA tokens are verified against the issuer's JWKS, fetched via HTTPS from the OIDC discovery endpoint. An attacker cannot forge a token for a trusted issuer without access to the cluster's private signing key.

Registry-issued tokens are verified against a local ECDSA key. With a persistent `signing_key`, this key should be protected with appropriate filesystem permissions (readable only by the registry process).

### Issuer confusion

The `issuers` allowlist is checked against the token's `iss` claim before any OIDC/JWKS lookup. This prevents:
- An attacker controlling an OIDC-compliant server from issuing tokens that appear valid.
- SSRF via a crafted `iss` claim pointing to an internal service.

When using prefix patterns (`https://oidc.example.com/id/*`), ensure the prefix is specific enough that no attacker-controlled issuer could match it.

### Token scope

Registry-issued tokens embed an explicit `access` claim listing exactly which repositories and actions were granted. `authorizeRegistryToken()` performs an exact match — a token for `repo/foo:pull` cannot be used to push, or to access `repo/bar`.

### Ephemeral key warning

When no `signing_key` is configured, the ephemeral key is logged as a warning at startup. Production deployments should always configure a persistent signing key.

### Catalog multi-tenancy

Without `catalog_prefix` policies, `/v2/_catalog` returns all repository names in the registry. In a multi-tenant deployment this leaks the existence of other tenants' repositories. Add a `catalog_prefix` to every tenant policy to restrict catalog responses to that tenant's namespace.

The filter is applied **after** storage retrieval, so it does not prevent the storage layer from reading all repository names internally. The goal is confidentiality of the response, not a storage-layer access control boundary.

**v1 limitation**: When a client holds a registry-issued token with `catalog_prefixes`, paginated catalog responses may return fewer than `n` entries per page (because filtering happens post-fetch). Next-page links are suppressed when filtering is active to avoid cursor drift. Clients should treat an absent `Link` header as end-of-list.

Direct SA-token requests (clients that present an SA token as the Bearer on `/v2/_catalog` instead of first exchanging it at the token endpoint) do not benefit from catalog filtering in v1. The `CatalogPrefixes` field is nil on the `Authorized()` OIDC path. Enforce catalog access via CEL policies that gate on `request["type"] == "registry"` if needed.

### Clock skew

Both SA token validation and registry JWT validation use a 60-second leeway (`ValidateWithLeeway`), consistent with the existing `token` provider.

---

## Testing

The implementation includes 30+ tests across four test files:

- **`accesscontroller_test.go`**: end-to-end `Authorized()` tests with a real ECDSA key pair and a `httptest.Server` mock OIDC/JWKS endpoint. Covers success, missing token, malformed token, wrong issuer, wrong audience, expired token, insufficient scope, multi-issuer policies, config validation, and WWW-Authenticate header format.

- **`tokenendpoint_test.go`**: token endpoint handler tests including full round-trip (SA token in → registry JWT out → `Authorized()` verifies it), denied scope omission, multi-scope requests, custom token expiry, method validation, and the `TokenEndpointer` interface.

- **`oidc_test.go`**: JWKS cache tests with mock HTTP server, covering discovery success/failure, key rotation (unknown kid triggers sync refresh), stale cache background refresh, and untrusted issuer rejection.

- **`policy_test.go`**: CEL compilation and evaluation tests covering valid and invalid expressions, first-match semantics, multi-issuer discrimination, per-action evaluation, live reload (valid file, invalid file keeps previous, unchanged file skips recompile).

---

## Dependency Summary

| Library | Role | Source |
|---|---|---|
| `github.com/go-jose/go-jose/v4` | JWT parsing, JWKS, ES256 signing | Already vendored |
| `github.com/go-jose/go-jose/v4/jwt` | `ParseSigned`, `Claims`, `ValidateWithLeeway` | Already vendored |
| `github.com/mitchellh/mapstructure` | Config struct decoding | Already vendored |
| `github.com/sirupsen/logrus` | Structured logging | Already vendored |
| `gopkg.in/yaml.v2` | Policy file parsing | Already vendored |
| `github.com/google/cel-go` | CEL expression compilation and evaluation | **Added** |
| `github.com/antlr4-go/antlr/v4` | Parser generator (transitive dep of cel-go) | **Added** |
| `cel.dev/expr` | CEL protobuf type definitions | Updated (was already an indirect dep) |
