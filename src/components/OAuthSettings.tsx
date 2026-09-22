import { useState } from 'react';
import {
  getOAuthSettings,
  saveOAuthSettings,
  resetOAuthSettings,
  resolveClientAssertionAudience,
  type ClientAssertionAlg,
  type ClientAssertionAudience,
  type ClientAuthMethod,
} from '../config/oauth';

interface OAuthSettingsProps {
  onSettingsChange: () => void;
}

const INPUT_CLASS =
  'mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500';

export function OAuthSettings({ onSettingsChange }: OAuthSettingsProps) {
  const [settings, setSettings] = useState(getOAuthSettings());
  const [isEditing, setIsEditing] = useState(false);

  const handleSave = () => {
    saveOAuthSettings(settings);
    setIsEditing(false);
    onSettingsChange();
  };

  const handleReset = () => {
    resetOAuthSettings();
    setSettings(getOAuthSettings());
    setIsEditing(false);
    onSettingsChange();
  };

  const usesPrivateKeyJwt = settings.clientAuthMethod === 'private_key_jwt';

  if (!isEditing) {
    return (
      <div className="mb-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-medium text-gray-900">OAuth Settings</h2>
          <button
            onClick={() => setIsEditing(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
          >
            Edit Settings
          </button>
        </div>
        <div className="bg-gray-50 p-4 rounded-md">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-sm font-medium text-gray-500">Base URL</p>
              <p className="text-sm text-gray-900">{settings.baseUrl}</p>
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500">Client ID</p>
              <p className="text-sm text-gray-900">{settings.clientId}</p>
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500">Client authentication</p>
              <p className="text-sm text-gray-900">
                {usesPrivateKeyJwt ? `private_key_jwt (${settings.clientAssertionAlg})` : 'client_secret_post'}
              </p>
            </div>
            {usesPrivateKeyJwt ? (
              <>
                <div>
                  <p className="text-sm font-medium text-gray-500">Assertion audience</p>
                  <p className="text-sm text-gray-900 break-all">{resolveClientAssertionAudience(settings)}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-500">jwks_uri</p>
                  <p className="text-sm text-gray-900 break-all">{settings.jwksPublicUrl}</p>
                </div>
              </>
            ) : (
              <div>
                <p className="text-sm font-medium text-gray-500">Client Secret</p>
                <p className="text-sm text-gray-900">••••••••</p>
              </div>
            )}
            <div>
              <p className="text-sm font-medium text-gray-500">Redirect URI</p>
              <p className="text-sm text-gray-900">{settings.redirectUri}</p>
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500">Protected Resource</p>
              <p className="text-sm text-gray-900">{settings.protectedResource}</p>
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500">Scope</p>
              <p className="text-sm text-gray-900">{settings.scope}</p>
            </div>
            <div>
              <p className="text-sm font-medium text-gray-500">DPoP (RFC 9449)</p>
              <p className="text-sm text-gray-900">{settings.dpopEnabled ? 'Enabled' : 'Disabled'}</p>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mb-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-medium text-gray-900">Edit OAuth Settings</h2>
        <div className="space-x-2">
          <button
            onClick={handleReset}
            className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700"
          >
            Reset to Default
          </button>
          <button
            onClick={handleSave}
            className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700"
          >
            Save Changes
          </button>
          <button
            onClick={() => setIsEditing(false)}
            className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700"
          >
            Cancel
          </button>
        </div>
      </div>
      <div className="bg-white p-4 rounded-md shadow">
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Base URL</label>
            <input
              type="text"
              value={settings.baseUrl}
              onChange={(e) => setSettings({ ...settings, baseUrl: e.target.value })}
              className={INPUT_CLASS}
              placeholder="https://your-oauth-server.com"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Client ID</label>
            <input
              type="text"
              value={settings.clientId}
              onChange={(e) => setSettings({ ...settings, clientId: e.target.value })}
              className={INPUT_CLASS}
              placeholder="your_client_id"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Client authentication</label>
            <select
              value={settings.clientAuthMethod}
              onChange={(e) =>
                setSettings({ ...settings, clientAuthMethod: e.target.value as ClientAuthMethod })
              }
              className={INPUT_CLASS}
            >
              <option value="client_secret_post">client_secret_post — shared secret in the request body</option>
              <option value="private_key_jwt">private_key_jwt — signed client_assertion (RFC 7523)</option>
            </select>
          </div>
          {usesPrivateKeyJwt ? (
            <div className="space-y-4 rounded-md border border-gray-200 p-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Assertion algorithm</label>
                <select
                  value={settings.clientAssertionAlg}
                  onChange={(e) =>
                    setSettings({ ...settings, clientAssertionAlg: e.target.value as ClientAssertionAlg })
                  }
                  className={INPUT_CLASS}
                >
                  <option value="RS256">RS256 — RSA 2048</option>
                  <option value="ES256">ES256 — EC P-256</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">Assertion audience (aud)</label>
                <select
                  value={settings.clientAssertionAudience}
                  onChange={(e) =>
                    setSettings({
                      ...settings,
                      clientAssertionAudience: e.target.value as ClientAssertionAudience,
                    })
                  }
                  className={INPUT_CLASS}
                >
                  <option value="token_endpoint">Token endpoint URL</option>
                  <option value="issuer">Issuer (base URL)</option>
                  <option value="custom">Custom value</option>
                </select>
                {settings.clientAssertionAudience === 'custom' ? (
                  <input
                    type="text"
                    value={settings.clientAssertionCustomAudience}
                    onChange={(e) =>
                      setSettings({ ...settings, clientAssertionCustomAudience: e.target.value })
                    }
                    className={INPUT_CLASS}
                    placeholder="https://your-oauth-server.com/oauth/token"
                  />
                ) : (
                  <p className="mt-1 text-xs text-gray-500 break-all">
                    Will be sent as: {resolveClientAssertionAudience(settings)}
                  </p>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">JWKS public URL</label>
                <input
                  type="text"
                  value={settings.jwksPublicUrl}
                  onChange={(e) => setSettings({ ...settings, jwksPublicUrl: e.target.value })}
                  className={INPUT_CLASS}
                  placeholder="http://localhost:8080/api/jwks"
                />
                <p className="mt-1 text-xs text-gray-500">
                  The URL at which the authorization server can reach this app's /api/jwks endpoint.
                  Change it when the server runs elsewhere (hostname, tunnel). Display only.
                </p>
              </div>
            </div>
          ) : (
            <div>
              <label className="block text-sm font-medium text-gray-700">Client Secret</label>
              <input
                type="password"
                value={settings.clientSecret}
                onChange={(e) => setSettings({ ...settings, clientSecret: e.target.value })}
                className={INPUT_CLASS}
                placeholder="your_client_secret"
              />
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700">Redirect URI</label>
            <input
              type="text"
              value={settings.redirectUri}
              onChange={(e) => setSettings({ ...settings, redirectUri: e.target.value })}
              className={INPUT_CLASS}
              placeholder="http://localhost:3000/callback"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Protected Resource</label>
            <input
              type="text"
              value={settings.protectedResource}
              onChange={(e) => setSettings({ ...settings, protectedResource: e.target.value })}
              className={INPUT_CLASS}
              placeholder="https://your-oauth-server.com/api/resource"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Scope</label>
            <input
              type="text"
              value={settings.scope}
              onChange={(e) => setSettings({ ...settings, scope: e.target.value })}
              className={INPUT_CLASS}
              placeholder="openid profile email"
            />
          </div>
          <div className="flex items-center">
            <input
              id="dpop-enabled"
              type="checkbox"
              checked={settings.dpopEnabled}
              onChange={(e) => setSettings({ ...settings, dpopEnabled: e.target.checked })}
              className="h-4 w-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <label htmlFor="dpop-enabled" className="ml-2 block text-sm font-medium text-gray-700">
              Enable DPoP (RFC 9449) — sender-constrained tokens
            </label>
          </div>
        </div>
      </div>
    </div>
  );
}
