import { createContext, useContext } from 'react';
import type { Credentials } from './types';

export interface AuthState {
  creds: Credentials | null;
  tokenCache: Map<string, string>;
  setCreds: (creds: Credentials | null) => void;
}

export const AuthContext = createContext<AuthState>({
  creds: null,
  tokenCache: new Map(),
  setCreds: () => {},
});

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
