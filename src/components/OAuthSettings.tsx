import { useState } from 'react';
import { getOAuthSettings, saveOAuthSettings, resetOAuthSettings } from '../config/oauth';

interface OAuthSettingsProps {
  onSettingsChange: () => void;
}

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
              <p className="text-sm font-medium text-gray-500">Client Secret</p>
              <p className="text-sm text-gray-900">••••••••</p>
            </div>
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
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
              placeholder="https://your-oauth-server.com"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Client ID</label>
            <input
              type="text"
              value={settings.clientId}
              onChange={(e) => setSettings({ ...settings, clientId: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
              placeholder="your_client_id"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Client Secret</label>
            <input
              type="password"
              value={settings.clientSecret}
              onChange={(e) => setSettings({ ...settings, clientSecret: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
              placeholder="your_client_secret"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Redirect URI</label>
            <input
              type="text"
              value={settings.redirectUri}
              onChange={(e) => setSettings({ ...settings, redirectUri: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
              placeholder="http://localhost:3000/callback"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Protected Resource</label>
            <input
              type="text"
              value={settings.protectedResource}
              onChange={(e) => setSettings({ ...settings, protectedResource: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
              placeholder="https://your-oauth-server.com/api/resource"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Scope</label>
            <input
              type="text"
              value={settings.scope}
              onChange={(e) => setSettings({ ...settings, scope: e.target.value })}
              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
              placeholder="openid profile email"
            />
          </div>
        </div>
      </div>
    </div>
  );
} 