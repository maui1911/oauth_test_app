export interface OAuthSettings {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  protectedResource: string;
  scope: string;
  dpopEnabled: boolean;
  endpoints: {
    authorize: string;
    token: string;
  };
}

const DEFAULT_SETTINGS: OAuthSettings = {
  baseUrl: "https://your-oauth-server.com",
  clientId: "your_client_id",
  clientSecret: "your_client_secret",
  redirectUri: "http://localhost:3000/callback",
  protectedResource: "https://your-oauth-server.com/api/resource",
  scope: "openid profile email",
  dpopEnabled: false,
  endpoints: {
    authorize: "/oauth/authorize",
    token: "/oauth/token",
  },
};

export function getOAuthSettings(): OAuthSettings {
  const storedSettings = localStorage.getItem("oauth_settings");
  if (storedSettings) {
    // Merge with defaults so newly added fields (e.g. dpopEnabled) get a value.
    return { ...DEFAULT_SETTINGS, ...JSON.parse(storedSettings) };
  }
  return DEFAULT_SETTINGS;
}

export const saveOAuthSettings = (settings: OAuthSettings) => {
  localStorage.setItem("oauth_settings", JSON.stringify(settings));
};

export const resetOAuthSettings = () => {
  localStorage.removeItem("oauth_settings");
};
