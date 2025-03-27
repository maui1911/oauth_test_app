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

export function getOAuthSettings(): OAuthSettings {
  return {
    baseUrl: import.meta.env.VITE_OAUTH_BASE_URL,
    clientId: import.meta.env.VITE_OAUTH_CLIENT_ID,
    clientSecret: import.meta.env.VITE_OAUTH_CLIENT_SECRET,
    redirectUri: import.meta.env.VITE_OAUTH_REDIRECT_URI,
    protectedResource: import.meta.env.VITE_OAUTH_PROTECTED_RESOURCE,
    scope: 'openid profile email',
    endpoints: {
      authorize: '/oauth2/authorize',
      token: '/oauth2/token'
    }
  };
}

export const saveOAuthSettings = (settings: OAuthSettings) => {
  localStorage.setItem('oauth_settings', JSON.stringify(settings));
};

export const resetOAuthSettings = () => {
  localStorage.removeItem('oauth_settings');
}; 