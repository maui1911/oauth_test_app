/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_OAUTH_BASE_URL: string;
  readonly VITE_OAUTH_CLIENT_ID: string;
  readonly VITE_OAUTH_CLIENT_SECRET: string;
  readonly VITE_OAUTH_REDIRECT_URI: string;
  readonly VITE_OAUTH_PROTECTED_RESOURCE: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
} 