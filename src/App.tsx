import { useState, useEffect } from 'react'
import { Tab } from '@headlessui/react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { OAuthService } from './services/oauthService'
import { Callback } from './components/Callback'
import { OAuthSettings } from './components/OAuthSettings'

function classNames(...classes: string[]) {
  return classes.filter(Boolean).join(' ')
}

function MainContent() {
  const [selectedFlow, setSelectedFlow] = useState<'authorization_code' | 'client_credentials'>('authorization_code')
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [refreshToken, setRefreshToken] = useState<string | null>(null)
  const [protectedResourceData, setProtectedResourceData] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const oauthService = OAuthService.getInstance()

  useEffect(() => {
    // Load tokens from localStorage on component mount
    setAccessToken(oauthService.getAccessToken())
    setRefreshToken(oauthService.getRefreshToken())
  }, [])

  const handleAuthorizationCodeFlow = async () => {
    try {
      setError(null);
      const url = await oauthService.getAuthorizationUrl();
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start authorization flow');
    }
  };

  const handleClientCredentialsFlow = async () => {
    try {
      setError(null)
      const response = await oauthService.getClientCredentialsToken()
      setAccessToken(response.access_token)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get client credentials token')
    }
  }

  const handleGetProtectedResource = async () => {
    try {
      setError(null)
      const data = await oauthService.getProtectedResource()
      setProtectedResourceData(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get protected resource')
    }
  }

  const handleClearTokens = () => {
    oauthService.clearTokens()
    setAccessToken(null)
    setRefreshToken(null)
    setProtectedResourceData(null)
  }

  const handleSettingsChange = () => {
    // Clear tokens when settings change to ensure we're using the new configuration
    handleClearTokens()
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="bg-white shadow rounded-lg p-6">
            <div className="flex justify-between items-center mb-6">
              <h1 className="text-2xl font-bold text-gray-900">OAuth 2.1 Test Application</h1>
              {accessToken && (
                <button
                  onClick={handleClearTokens}
                  className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700"
                >
                  Clear Tokens
                </button>
              )}
            </div>

            <OAuthSettings onSettingsChange={handleSettingsChange} />
            
            <Tab.Group selectedIndex={selectedFlow === 'authorization_code' ? 0 : 1} onChange={(index) => setSelectedFlow(index === 0 ? 'authorization_code' : 'client_credentials')}>
              <Tab.List className="flex space-x-1 rounded-xl bg-blue-900/20 p-1">
                <Tab
                  className={({ selected }) =>
                    classNames(
                      'w-full rounded-lg py-2.5 text-sm font-medium leading-5',
                      'ring-white ring-opacity-60 ring-offset-2 ring-offset-blue-400 focus:outline-none focus:ring-2',
                      selected
                        ? 'bg-white text-blue-700 shadow'
                        : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
                    )
                  }
                >
                  Authorization Code Flow
                </Tab>
                <Tab
                  className={({ selected }) =>
                    classNames(
                      'w-full rounded-lg py-2.5 text-sm font-medium leading-5',
                      'ring-white ring-opacity-60 ring-offset-2 ring-offset-blue-400 focus:outline-none focus:ring-2',
                      selected
                        ? 'bg-white text-blue-700 shadow'
                        : 'text-blue-100 hover:bg-white/[0.12] hover:text-white'
                    )
                  }
                >
                  Client Credentials Flow
                </Tab>
              </Tab.List>
            </Tab.Group>

            <div className="mt-6">
              {error && (
                <div className="mb-4 p-4 bg-red-50 text-red-700 rounded-md">
                  {error}
                </div>
              )}

              {selectedFlow === 'authorization_code' ? (
                <div>
                  <h2 className="text-lg font-medium text-gray-900 mb-4">Authorization Code Flow</h2>
                  <div className="space-y-4">
                    <button
                      className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
                      onClick={handleAuthorizationCodeFlow}
                    >
                      Start Authorization Code Flow
                    </button>
                    {accessToken && (
                      <div className="mt-4">
                        <h3 className="text-sm font-medium text-gray-700">Access Token:</h3>
                        <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                          {accessToken}
                        </pre>
                      </div>
                    )}
                    {refreshToken && (
                      <div className="mt-4">
                        <h3 className="text-sm font-medium text-gray-700">Refresh Token:</h3>
                        <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                          {refreshToken}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div>
                  <h2 className="text-lg font-medium text-gray-900 mb-4">Client Credentials Flow</h2>
                  <div className="space-y-4">
                    <button
                      className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
                      onClick={handleClientCredentialsFlow}
                    >
                      Start Client Credentials Flow
                    </button>
                    {accessToken && (
                      <div className="mt-4">
                        <h3 className="text-sm font-medium text-gray-700">Access Token:</h3>
                        <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                          {accessToken}
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {accessToken && (
                <div className="mt-6">
                  <h2 className="text-lg font-medium text-gray-900 mb-4">Protected Resource</h2>
                  <button
                    className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700"
                    onClick={handleGetProtectedResource}
                  >
                    Get Protected Resource
                  </button>
                  {protectedResourceData && (
                    <div className="mt-4">
                      <h3 className="text-sm font-medium text-gray-700">Response:</h3>
                      <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-96">
                        {JSON.stringify(protectedResourceData, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<MainContent />} />
        <Route path="/callback" element={<Callback />} />
      </Routes>
    </Router>
  )
}

export default App 