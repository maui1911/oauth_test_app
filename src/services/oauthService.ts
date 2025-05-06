import { getOAuthSettings } from '../config/oauth';

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

export class OAuthService {
  private static instance: OAuthService;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private codeVerifier: string | null = null;
  private state: string | null = null;

  private constructor() {
    // Load tokens from localStorage on initialization
    this.accessToken = localStorage.getItem('access_token');
    this.refreshToken = localStorage.getItem('refresh_token');
    this.codeVerifier = localStorage.getItem('code_verifier');
    this.state = localStorage.getItem('oauth_state');
  }

  public static getInstance(): OAuthService {
    if (!OAuthService.instance) {
      OAuthService.instance = new OAuthService();
    }
    return OAuthService.instance;
  }

  private generateCodeVerifier(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64URLEncode(array);
  }

  private async generateCodeChallenge(verifier: string): Promise<string> {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return base64URLEncode(new Uint8Array(hash));
  }

  public async getAuthorizationUrl(): Promise<string> {
    const settings = getOAuthSettings();
    this.codeVerifier = this.generateCodeVerifier();
    this.state = this.generateState();
    const codeChallenge = await this.generateCodeChallenge(this.codeVerifier);

    // Store code verifier and state in localStorage
    localStorage.setItem('code_verifier', this.codeVerifier);
    localStorage.setItem('oauth_state', this.state);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: settings.clientId,
      redirect_uri: settings.redirectUri,
      scope: settings.scope,
      state: this.state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });

    return `${settings.baseUrl}${settings.endpoints.authorize}?${params.toString()}`;
  }

  public async exchangeCodeForTokens(code: string, state: string): Promise<TokenResponse> {
    // Verify state matches
    if (state !== this.state) {
      throw new Error('Invalid state parameter');
    }

    if (!this.codeVerifier) {
      throw new Error('Code verifier not found. Please start the authorization flow again.');
    }

    const settings = getOAuthSettings();
    const response = await fetch('/api/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tokenUrl: `${settings.baseUrl}${settings.endpoints.token}`,
        clientId: settings.clientId,
        clientSecret: settings.clientSecret,
        code,
        redirectUri: settings.redirectUri,
        codeVerifier: this.codeVerifier,
        grantType: 'authorization_code',
        scope: settings.scope,
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to exchange code for tokens');
    }

    const data = await response.json();
    this.setTokens(data);
    this.clearAuthData(); // Clear code verifier and state after successful exchange
    return data;
  }

  public async getClientCredentialsToken(): Promise<TokenResponse> {
    const settings = getOAuthSettings();
    const response = await fetch('/api/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tokenUrl: `${settings.baseUrl}${settings.endpoints.token}`,
        clientId: settings.clientId,
        clientSecret: settings.clientSecret,
        grantType: 'client_credentials',
        scope: settings.scope,
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to get client credentials token');
    }

    const data = await response.json();
    this.setTokens(data);
    return data;
  }

  public async refreshAccessToken(): Promise<TokenResponse> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    const settings = getOAuthSettings();
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: this.refreshToken,
      client_id: settings.clientId,
      client_secret: settings.clientSecret,
    });

    const response = await fetch(`${settings.baseUrl}${settings.endpoints.token}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });

    if (!response.ok) {
      throw new Error('Failed to refresh token');
    }

    const data = await response.json();
    this.setTokens(data);
    return data;
  }

  public async getProtectedResource(): Promise<any> {
    if (!this.accessToken) {
      throw new Error('No access token available');
    }

    const settings = getOAuthSettings();
    console.log('Requesting protected resource:', settings.protectedResource);
    
    try {
      const response = await fetch('/api/proxy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.accessToken}`,
        },
        body: JSON.stringify({ url: settings.protectedResource }),
      });

      console.log('Protected resource response status:', response.status);
      
      if (!response.ok) {
        if (response.status === 401 && this.refreshToken) {
          console.log('Access token expired, refreshing...');
          await this.refreshAccessToken();
          return this.getProtectedResource();
        }
        
        const errorData = await response.text();
        console.error('Protected resource error:', errorData);
        
        try {
          // Try to parse as JSON if possible
          const jsonError = JSON.parse(errorData);
          throw new Error(`Failed to get protected resource: ${jsonError.error || 'Unknown error'}`);
        } catch (e) {
          // If parsing fails, use the text response
          throw new Error(`Failed to get protected resource: ${errorData || response.statusText}`);
        }
      }

      // Handle different response types
      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return response.json();
      } else {
        const text = await response.text();
        console.log('Non-JSON response received, trying to parse...');
        try {
          return JSON.parse(text);
        } catch (e) {
          return { text };
        }
      }
    } catch (error) {
      console.error('Error fetching protected resource:', error);
      throw error;
    }
  }

  private setTokens(data: TokenResponse): void {
    this.accessToken = data.access_token;
    if (data.refresh_token) {
      this.refreshToken = data.refresh_token;
    }

    // Store tokens in localStorage
    localStorage.setItem('access_token', data.access_token);
    if (data.refresh_token) {
      localStorage.setItem('refresh_token', data.refresh_token);
    }
  }

  private generateState(): string {
    return Math.random().toString(36).substring(7);
  }

  public getAccessToken(): string | null {
    return this.accessToken;
  }

  public getRefreshToken(): string | null {
    return this.refreshToken;
  }

  private clearAuthData(): void {
    this.codeVerifier = null;
    this.state = null;
    localStorage.removeItem('code_verifier');
    localStorage.removeItem('oauth_state');
  }

  public clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    this.clearAuthData();
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  }
}

// Helper function to encode base64URL
function base64URLEncode(buffer: Uint8Array): string {
  return btoa(String.fromCharCode(...buffer))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}