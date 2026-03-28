import type { Credentials, ManifestV2, ManifestList, ImageConfig, TagInfo } from './types';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function basicAuth(creds: Credentials): string {
  return 'Basic ' + btoa(`${creds.username}:${creds.token}`);
}

interface BearerChallenge {
  realm: string;
  service: string;
  scope: string;
}

function parseBearerChallenge(header: string): BearerChallenge | null {
  const realmMatch = header.match(/realm="([^"]+)"/);
  const serviceMatch = header.match(/service="([^"]+)"/);
  const scopeMatch = header.match(/scope="([^"]+)"/);
  if (!realmMatch) return null;
  return {
    realm: realmMatch[1],
    service: serviceMatch ? serviceMatch[1] : '',
    scope: scopeMatch ? scopeMatch[1] : '',
  };
}

// ---------------------------------------------------------------------------
// Token acquisition
// ---------------------------------------------------------------------------

/**
 * Fetches a token from the token endpoint.
 * scope === '' means no scope (catalog / initial auth).
 * creds === null means anonymous (no Authorization header sent).
 */
async function fetchToken(
  realm: string,
  service: string,
  scope: string,
  creds: Credentials | null,
): Promise<string> {
  const url = new URL(realm);
  if (service) url.searchParams.set('service', service);
  if (scope) url.searchParams.set('scope', scope);

  const headers: Record<string, string> = {};
  if (creds) headers['Authorization'] = basicAuth(creds);

  const res = await fetch(url.toString(), { headers });
  if (!res.ok) {
    throw new Error(`Token fetch failed: ${res.status} ${res.statusText}`);
  }
  const body = await res.json() as { token?: string; access_token?: string };
  const jwt = body.token ?? body.access_token;
  if (!jwt) throw new Error('No token in response');
  return jwt;
}

/**
 * Initial login: exchanges credentials for a registry JWT with no scope.
 * Pass null to attempt an anonymous token (for public access paths).
 * Returns the JWT string, or '' if the registry requires no auth.
 */
export async function login(creds: Credentials | null, scope = ''): Promise<string> {
  const headers: Record<string, string> = {};
  if (creds) headers['Authorization'] = basicAuth(creds);
  // First hit /v2/ to get the WWW-Authenticate header pointing at the realm.
  const res = await fetch('/v2/', { headers });

  if (res.status === 401) {
    const wwwAuth = res.headers.get('WWW-Authenticate') ?? '';
    const challenge = parseBearerChallenge(wwwAuth);
    if (!challenge) {
      throw new Error('Unrecognised WWW-Authenticate header: ' + wwwAuth);
    }
    return fetchToken(challenge.realm, challenge.service, scope, creds);
  }

  if (res.ok) {
    // Registry doesn't require auth – return a sentinel empty string so the
    // rest of the UI still works with no Bearer header.
    return '';
  }

  throw new Error(`Unexpected status from /v2/: ${res.status}`);
}

// ---------------------------------------------------------------------------
// Authenticated fetch with automatic token refresh
// ---------------------------------------------------------------------------

// In-flight token fetches keyed by scope. Concurrent 401s for the same scope
// share one fetch instead of each firing independently (thundering herd).
const inflightTokens = new Map<string, Promise<string>>()

async function acquireToken(
  realm: string,
  service: string,
  scope: string,
  creds: Credentials | null,
  tokenCache: Map<string, string>,
): Promise<string> {
  const cached = tokenCache.get(scope)
  if (cached) return cached

  const existing = inflightTokens.get(scope)
  if (existing) return existing

  const p = fetchToken(realm, service, scope, creds)
    .then(jwt => {
      tokenCache.set(scope, jwt)
      inflightTokens.delete(scope)
      return jwt
    })
    .catch(err => {
      inflightTokens.delete(scope)
      throw err
    })
  inflightTokens.set(scope, p)
  return p
}

/**
 * Performs an authenticated fetch against the registry.
 * On 401 it parses the WWW-Authenticate challenge, obtains a scoped token,
 * caches it, and retries once.
 * creds === null means anonymous — scoped tokens are fetched without credentials.
 */
export async function fetchRegistry(
  url: string,
  method: string,
  creds: Credentials | null,
  tokenCache: Map<string, string>,
  body?: string,
  extraHeaders?: Record<string, string>,
): Promise<Response> {
  const buildHeaders = (jwt: string | undefined): HeadersInit => {
    const h: Record<string, string> = { ...extraHeaders };
    if (jwt) h['Authorization'] = `Bearer ${jwt}`;
    if (body !== undefined) h['Content-Type'] = 'application/json';
    return h;
  };

  // Derive a best-effort scope key from the URL to look up a cached token.
  const scopeKey = deriveScopeKey(url);
  let jwt = tokenCache.get(scopeKey) ?? tokenCache.get('');

  const doFetch = (token: string | undefined) =>
    fetch(url, { method, headers: buildHeaders(token), body });

  let res = await doFetch(jwt);

  if (res.status === 401) {
    const wwwAuth = res.headers.get('WWW-Authenticate') ?? '';
    const challenge = parseBearerChallenge(wwwAuth);
    if (!challenge) throw new Error('Cannot parse WWW-Authenticate: ' + wwwAuth);

    const newJwt = await acquireToken(challenge.realm, challenge.service, challenge.scope, creds, tokenCache);
    if (scopeKey !== challenge.scope) tokenCache.set(scopeKey, newJwt);

    res = await doFetch(newJwt);
  }

  return res;
}

/**
 * Derive a rough scope key from a /v2/ URL so we can look up a cached token
 * without making a request first. This is a best-effort optimisation only.
 */
function deriveScopeKey(url: string): string {
  // /v2/<name>/manifests/<ref>  → repository:<name>:pull (or pull,delete for DELETE)
  // /v2/<name>/tags/list        → repository:<name>:pull
  // /v2/<name>/blobs/<digest>   → repository:<name>:pull
  // /v2/_catalog                → registry:catalog:*
  const catalogRe = /\/v2\/_catalog/;
  if (catalogRe.test(url)) return 'registry:catalog:*';

  const repoRe = /\/v2\/([^/].+?)\/(manifests|tags|blobs)/;
  const m = url.match(repoRe);
  if (m) return `repository:${m[1]}:pull`;

  return '';
}

// ---------------------------------------------------------------------------
// Registry API calls
// ---------------------------------------------------------------------------

export async function getCatalog(
  creds: Credentials | null,
  tokenCache: Map<string, string>,
): Promise<string[]> {
  const all: string[] = [];
  let url = '/v2/_catalog?n=1000';
  while (url) {
    const res = await fetchRegistry(url, 'GET', creds, tokenCache);
    if (!res.ok) throw new Error(`getCatalog failed: ${res.status}`);
    const body = await res.json() as { repositories: string[] | null };
    const page = body.repositories ?? [];
    all.push(...page);
    // Follow RFC 5988 Link header: Link: </v2/_catalog?last=x&n=1000>; rel="next"
    const link = res.headers.get('Link') ?? '';
    const next = link.match(/<([^>]+)>;\s*rel="next"/);
    url = next ? next[1] : '';
  }
  return all;
}

export async function getTags(
  repo: string,
  creds: Credentials | null,
  tokenCache: Map<string, string>,
): Promise<string[]> {
  const res = await fetchRegistry(`/v2/${repo}/tags/list`, 'GET', creds, tokenCache);
  if (!res.ok) throw new Error(`getTags failed: ${res.status}`);
  const body = await res.json() as { tags: string[] | null };
  return body.tags ?? [];
}

const MANIFEST_ACCEPT = [
  'application/vnd.docker.distribution.manifest.v2+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.oci.image.index.v1+json',
].join(', ');

export interface ManifestResult {
  digest: string;
  manifest: ManifestV2 | ManifestList;
}

export async function getManifest(
  repo: string,
  ref: string,
  creds: Credentials | null,
  tokenCache: Map<string, string>,
): Promise<ManifestResult> {
  const res = await fetchRegistry(
    `/v2/${repo}/manifests/${ref}`,
    'GET',
    creds,
    tokenCache,
    undefined,
    { Accept: MANIFEST_ACCEPT },
  );
  if (!res.ok) throw new Error(`getManifest failed: ${res.status}`);
  const digest = res.headers.get('Docker-Content-Digest') ?? ref;
  const manifest = await res.json() as ManifestV2 | ManifestList;
  return { digest, manifest };
}

export async function getImageConfig(
  repo: string,
  configDigest: string,
  creds: Credentials | null,
  tokenCache: Map<string, string>,
): Promise<ImageConfig> {
  const res = await fetchRegistry(
    `/v2/${repo}/blobs/${configDigest}`,
    'GET',
    creds,
    tokenCache,
  );
  if (!res.ok) throw new Error(`getImageConfig failed: ${res.status}`);
  return res.json() as Promise<ImageConfig>;
}

export async function deleteManifest(
  repo: string,
  digest: string,
  creds: Credentials | null,
  tokenCache: Map<string, string>,
): Promise<void> {
  const res = await fetchRegistry(
    `/v2/${repo}/manifests/${digest}`,
    'DELETE',
    creds,
    tokenCache,
  );
  if (!res.ok && res.status !== 202) {
    throw new Error(`deleteManifest failed: ${res.status}`);
  }
}

// ---------------------------------------------------------------------------
// High-level: resolve full TagInfo for a single tag
// ---------------------------------------------------------------------------

export async function resolveTagInfo(
  repo: string,
  tag: string,
  creds: Credentials | null,
  tokenCache: Map<string, string>,
): Promise<TagInfo> {
  const { digest, manifest } = await getManifest(repo, tag, creds, tokenCache);

  // Handle manifest list / OCI index by resolving the first entry
  if ('manifests' in manifest) {
    const first = manifest.manifests[0];
    if (first) {
      return resolveTagInfo(repo, first.digest, creds, tokenCache).then(info => ({
        ...info,
        name: tag,
        digest,
      }));
    }
    return { name: tag, digest, size: 0 };
  }

  // ManifestV2
  const m = manifest as ManifestV2;
  const totalSize = m.layers.reduce((s, l) => s + l.size, 0);
  const layers = m.layers.map(l => ({ digest: l.digest, size: l.size }));

  return { name: tag, digest, size: totalSize, layers, configDigest: m.config?.digest };
}
