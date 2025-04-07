export interface OAuthSettings {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  protectedResource: string;
  scope: string;
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
  endpoints: {
    authorize: "/connect/authorize",
    token: "/connect/token",
  },
};

export function getOAuthSettings(): OAuthSettings {
  const storedSettings = localStorage.getItem("oauth_settings");
  if (storedSettings) {
    return JSON.parse(storedSettings);
  }
  return DEFAULT_SETTINGS;
}

export const saveOAuthSettings = (settings: OAuthSettings) => {
  localStorage.setItem("oauth_settings", JSON.stringify(settings));
};

export const resetOAuthSettings = () => {
  localStorage.removeItem("oauth_settings");
};
