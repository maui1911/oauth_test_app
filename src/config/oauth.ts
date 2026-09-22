export type ClientAuthMethod = "client_secret_post" | "private_key_jwt";
export type ClientAssertionAlg = "RS256" | "ES256";
/** Which value goes into the assertion's aud claim; servers differ in what they accept. */
export type ClientAssertionAudience = "token_endpoint" | "issuer" | "custom";

export interface OAuthSettings {
  baseUrl: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  protectedResource: string;
  scope: string;
  dpopEnabled: boolean;
  clientAuthMethod: ClientAuthMethod;
  clientAssertionAlg: ClientAssertionAlg;
  clientAssertionAudience: ClientAssertionAudience;
  clientAssertionCustomAudience: string;
  /** Display only: the URL the authorization server should fetch, which may differ from localhost. */
  jwksPublicUrl: string;
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
  clientAuthMethod: "client_secret_post",
  clientAssertionAlg: "RS256",
  clientAssertionAudience: "token_endpoint",
  clientAssertionCustomAudience: "",
  jwksPublicUrl: "http://localhost:8080/api/jwks",
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

export function getTokenUrl(settings: OAuthSettings): string {
  return `${settings.baseUrl}${settings.endpoints.token}`;
}

/** The aud value the client assertion will carry under the current settings. */
export function resolveClientAssertionAudience(settings: OAuthSettings): string {
  switch (settings.clientAssertionAudience) {
    case "issuer":
      return settings.baseUrl;
    case "custom":
      return settings.clientAssertionCustomAudience;
    default:
      return getTokenUrl(settings);
  }
}

export const saveOAuthSettings = (settings: OAuthSettings) => {
  localStorage.setItem("oauth_settings", JSON.stringify(settings));
};

export const resetOAuthSettings = () => {
  localStorage.removeItem("oauth_settings");
};
