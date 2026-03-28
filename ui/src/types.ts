export interface Credentials {
  username: string;
  token: string; // OIDC token
}

export interface ManifestV2 {
  schemaVersion: 2;
  mediaType: string;
  config: { mediaType: string; size: number; digest: string };
  layers: Array<{ mediaType: string; size: number; digest: string }>;
}

export interface ManifestList {
  schemaVersion: 2;
  mediaType: string;
  manifests: Array<{
    mediaType: string;
    size: number;
    digest: string;
    platform?: { architecture: string; os: string };
  }>;
}

export interface ImageConfig {
  architecture?: string;
  os?: string;
  created?: string;
  config?: Record<string, unknown>;
  rootfs?: { type: string; diff_ids: string[] };
  history?: Array<{ created?: string; created_by?: string; empty_layer?: boolean }>;
}

export interface TagInfo {
  name: string;
  digest: string;
  size: number; // sum of layer sizes
  created?: string;
  architecture?: string;
  os?: string;
  layers?: Array<{ digest: string; size: number }>;
  configDigest?: string;
}

export type Page =
  | { kind: 'login' }
  | { kind: 'catalog' }
  | { kind: 'repo'; repo: string };
