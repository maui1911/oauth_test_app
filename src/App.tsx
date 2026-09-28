import { useState, useEffect } from 'react'
import { Tab } from '@headlessui/react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import { OAuthService } from './services/oauthService'
import { Callback } from './components/Callback'
import { OAuthSettings } from './components/OAuthSettings'
import { ConnectorManager } from './components/ConnectorManager'
import { PerformanceTester } from './components/PerformanceTester'
import { DpopFaultInjector } from './components/DpopFaultInjector'
import { ClientKeysPanel } from './components/ClientKeysPanel'
import { DPoPService } from './services/dpopService'
import { findFault, type DpopFaultKey } from './services/dpopFaults'
import {
  AUTHORIZE_VARIANTS,
  findAuthorizeVariant,
  type AuthorizeVariantKey,
} from './services/authorizeVariants'
import { getOAuthSettings } from './config/oauth'

function classNames(...classes: string[]) {
  return classes.filter(Boolean).join(' ')
}

function decodeBase64Url(part: string): any {
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4))
  return JSON.parse(atob(b64 + pad))
}

function decodeJwt(token: string): { header: any; payload: any } | null {
  try {
    const [header, payload] = token.split('.')
    return { header: decodeBase64Url(header), payload: decodeBase64Url(payload) }
  } catch {
    return null
  }
}

function JwtDump({ title, token }: { title: string; token: string }) {
  const decoded = decodeJwt(token)
  return (
    <div className="mt-4">
      <h3 className="text-sm font-medium text-gray-700">{title}</h3>
      <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-32">
        {token}
      </pre>
      {decoded && (
        <div className="mt-2">
          <h4 className="text-xs font-medium text-gray-500">Decoded header:</h4>
          <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-48">
            {JSON.stringify(decoded.header, null, 2)}
          </pre>
          <h4 className="text-xs font-medium text-gray-500 mt-2">Decoded payload:</h4>
          <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-48">
            {JSON.stringify(decoded.payload, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

function MainContent() {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [settings, setSettings] = useState(getOAuthSettings())
  const [selectedFlow, setSelectedFlow] = useState<'authorization_code' | 'client_credentials'>('authorization_code')
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [refreshToken, setRefreshToken] = useState<string | null>(null)
  const [protectedResourceData, setProtectedResourceData] = useState<any>(null)
  const [dpopProof, setDpopProof] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [tokenType, setTokenType] = useState<string | null>(null)
  const [dpopThumbprint, setDpopThumbprint] = useState<string | null>(null)
  const [armedFault, setArmedFault] = useState<DpopFaultKey | null>(null)
  const [clientAssertion, setClientAssertion] = useState<string | null>(null)
  const [authorizeVariant, setAuthorizeVariant] = useState<AuthorizeVariantKey>('none')
  const [renewalChallenge, setRenewalChallenge] = useState<string | null>(null)
  const oauthService = OAuthService.getInstance()

  // Kept visible app-wide: an armed fault survives until some request consumes it, and without a
  // reminder it is easy to spend it on an unrelated request and then hunt a failure you caused.
  useEffect(() => {
    const dpop = DPoPService.getInstance()
    setArmedFault(dpop.getArmedFault())
    return dpop.onArmedFaultChange(setArmedFault)
  }, [])

  useEffect(() => {
    // Load tokens from localStorage on component mount
    setAccessToken(oauthService.getAccessToken())
    setRefreshToken(oauthService.getRefreshToken())
    setTokenType(oauthService.getTokenType())
    // Survives the authorization code redirect: the callback route exchanges the code on this same
    // service instance before navigating here.
    setClientAssertion(oauthService.getLastClientAssertion())
    setError(oauthService.getAuthorizationOutcome())
    if (getOAuthSettings().dpopEnabled) {
      DPoPService.getInstance().getThumbprint().then(setDpopThumbprint).catch(() => {})
    }
  }, [])

  // A resource call may have renewed the tokens along the way.
  const syncTokens = () => {
    setAccessToken(oauthService.getAccessToken())
    setRefreshToken(oauthService.getRefreshToken())
    setTokenType(oauthService.getTokenType())
  }

  const handleAuthorizationCodeFlow = async () => {
    try {
      setError(null);
      const url = await oauthService.getAuthorizationUrl(authorizeVariant);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start authorization flow');
    }
  };

  const handleClientCredentialsFlow = async () => {
    try {
      setError(null)
      await oauthService.getClientCredentialsToken()
      syncTokens()
      if (getOAuthSettings().dpopEnabled) {
        DPoPService.getInstance().getThumbprint().then(setDpopThumbprint).catch(() => {})
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get client credentials token')
    } finally {
      // Shown on failure too: a rejected assertion is what needs inspecting.
      setClientAssertion(oauthService.getLastClientAssertion())
    }
  }

  const callProtectedResource = async (call: () => Promise<any>) => {
    try {
      setError(null)
      setProtectedResourceData(null)
      setProtectedResourceData(await call())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to get protected resource')
    } finally {
      setDpopProof(oauthService.getLastDpopProof())
      setRenewalChallenge(oauthService.getLastRenewalChallenge())
      syncTokens()
    }
  }

  const handleGetProtectedResource = () =>
    callProtectedResource(() => oauthService.getProtectedResource())

  const handleGetProtectedResourceWithoutToken = () =>
    callProtectedResource(() => oauthService.getProtectedResourceWithoutToken())

  const handleClearTokens = () => {
    oauthService.clearTokens()
    setAccessToken(null)
    setRefreshToken(null)
    setProtectedResourceData(null)
    setDpopProof(null)
    setTokenType(null)
    setClientAssertion(null)
    setRenewalChallenge(null)
  }

  const handleSettingsChange = () => {
    // Clear tokens when settings change to ensure we're using the new configuration
    handleClearTokens()
    setSettings(getOAuthSettings())
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

            {settings.clientAuthMethod === 'private_key_jwt' && (
              <ClientKeysPanel jwksPublicUrl={settings.jwksPublicUrl} />
            )}

            {armedFault && (
              <div className="mb-6 flex items-center justify-between gap-4 rounded-md border border-amber-400 bg-amber-50 p-3">
                <p className="text-sm text-amber-900">
                  A deliberate DPoP fault is armed:{' '}
                  <span className="font-semibold">{findFault(armedFault)?.label ?? armedFault}</span>
                  . It applies to every request until you disarm it
                  {findFault(armedFault)?.allowsNonceRetry ? '.' : ', and the automatic nonce retry is skipped.'}
                </p>
                <button
                  onClick={() => DPoPService.getInstance().armFault(null)}
                  className="shrink-0 rounded-md bg-amber-600 px-3 py-1.5 text-sm text-white hover:bg-amber-700"
                >
                  Disarm
                </button>
              </div>
            )}
            
            <Tab.Group selectedIndex={selectedIndex} onChange={setSelectedIndex}>
              <Tab.List className="flex space-x-1 rounded-xl bg-blue-900/20 p-1 mb-6">
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
                  OAuth Flows
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
                  API Connectors
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
                  Performance Testing
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
                  DPoP Faults
                </Tab>
              </Tab.List>
              <Tab.Panels>
                <Tab.Panel>
                  {/* OAuth Flows Tab */}
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
                      <div className="mb-4 p-4 bg-red-50 text-red-700 rounded-md whitespace-pre-line break-words">
                        {error}
                      </div>
                    )}

                    {selectedFlow === 'authorization_code' ? (
                      <div>
                        <h2 className="text-lg font-medium text-gray-900 mb-4">Authorization Code Flow</h2>
                        <div className="space-y-4">
                          <div className="max-w-xl">
                            <label className="block text-sm font-medium text-gray-700">Authorize request</label>
                            <select
                              value={authorizeVariant}
                              onChange={(e) => setAuthorizeVariant(e.target.value as AuthorizeVariantKey)}
                              className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                            >
                              {AUTHORIZE_VARIANTS.map((variant) => (
                                <option key={variant.key} value={variant.key}>
                                  {variant.label}
                                </option>
                              ))}
                            </select>
                            <p className="mt-1 text-xs text-gray-500">
                              Expected: {findAuthorizeVariant(authorizeVariant).expected}
                            </p>
                          </div>
                          <button
                            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
                            onClick={handleAuthorizationCodeFlow}
                          >
                            Start Authorization Code Flow
                          </button>
                          {accessToken && (
                            <div className="mt-4">
                              <p className="text-xs text-gray-500 mb-1">
                                Token type: <span className="font-semibold">{tokenType || 'Bearer'}</span>
                                {tokenType?.toUpperCase() === 'DPOP' && dpopThumbprint && (
                                  <span> · jkt: <span className="font-mono">{dpopThumbprint}</span></span>
                                )}
                              </p>
                              <h3 className="text-sm font-medium text-gray-700">Access Token:</h3>
                              <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                                {accessToken}
                              </pre>
                              {(() => {
                                const decoded = decodeJwt(accessToken)
                                return decoded ? (
                                  <div className="mt-2">
                                    <h4 className="text-xs font-medium text-gray-500">Decoded header:</h4>
                                    <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-48">
                                      {JSON.stringify(decoded.header, null, 2)}
                                    </pre>
                                    <h4 className="text-xs font-medium text-gray-500 mt-2">Decoded payload:</h4>
                                    <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-48">
                                      {JSON.stringify(decoded.payload, null, 2)}
                                    </pre>
                                  </div>
                                ) : null
                              })()}
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
                              <p className="text-xs text-gray-500 mb-1">
                                Token type: <span className="font-semibold">{tokenType || 'Bearer'}</span>
                                {tokenType?.toUpperCase() === 'DPOP' && dpopThumbprint && (
                                  <span> · jkt: <span className="font-mono">{dpopThumbprint}</span></span>
                                )}
                              </p>
                              <h3 className="text-sm font-medium text-gray-700">Access Token:</h3>
                              <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                                {accessToken}
                              </pre>
                              {(() => {
                                const decoded = decodeJwt(accessToken)
                                return decoded ? (
                                  <div className="mt-2">
                                    <h4 className="text-xs font-medium text-gray-500">Decoded header:</h4>
                                    <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-48">
                                      {JSON.stringify(decoded.header, null, 2)}
                                    </pre>
                                    <h4 className="text-xs font-medium text-gray-500 mt-2">Decoded payload:</h4>
                                    <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-48">
                                      {JSON.stringify(decoded.payload, null, 2)}
                                    </pre>
                                  </div>
                                ) : null
                              })()}
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {clientAssertion && (
                      <JwtDump title="Client assertion (sent to token endpoint):" token={clientAssertion} />
                    )}

                    <div className="mt-6">
                      <h2 className="text-lg font-medium text-gray-900 mb-4">Protected Resource</h2>
                      <div className="flex flex-wrap gap-2">
                        {accessToken && (
                          <button
                            className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700"
                            onClick={handleGetProtectedResource}
                          >
                            Get Protected Resource
                          </button>
                        )}
                        <button
                          className="bg-gray-100 text-gray-800 px-4 py-2 rounded-md hover:bg-gray-200"
                          onClick={handleGetProtectedResourceWithoutToken}
                        >
                          Call without token
                        </button>
                      </div>
                      {renewalChallenge && (
                        <p className="mt-2 text-xs text-gray-600">
                          Token renewal triggered by HTTP 401 with{' '}
                          <span className="font-mono break-all">WWW-Authenticate: {renewalChallenge}</span>
                        </p>
                      )}
                      {protectedResourceData && (
                        <div className="mt-4">
                          <h3 className="text-sm font-medium text-gray-700">Response:</h3>
                          <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-96">
                            {JSON.stringify(protectedResourceData, null, 2)}
                          </pre>
                        </div>
                      )}
                      {dpopProof && (
                        <div className="mt-4">
                          <h3 className="text-sm font-medium text-gray-700">DPoP Proof (sent to resource server):</h3>
                          <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                            {dpopProof}
                          </pre>
                          {(() => {
                            const decoded = decodeJwt(dpopProof)
                            return decoded ? (
                              <div className="mt-2">
                                <h4 className="text-xs font-medium text-gray-500">Decoded header:</h4>
                                <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-48">
                                  {JSON.stringify(decoded.header, null, 2)}
                                </pre>
                                <h4 className="text-xs font-medium text-gray-500 mt-2">Decoded payload:</h4>
                                <pre className="mt-1 text-sm text-gray-500 bg-gray-50 p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-48">
                                  {JSON.stringify(decoded.payload, null, 2)}
                                </pre>
                              </div>
                            ) : null
                          })()}
                        </div>
                      )}
                    </div>
                  </div>
                </Tab.Panel>
                <Tab.Panel>
                  {/* API Connectors Tab */}
                  <div className="mt-4">
                    <ConnectorManager />
                  </div>
                </Tab.Panel>
                <Tab.Panel>
                  {/* Performance Testing Tab */}
                  <div className="mt-4">
                    <PerformanceTester />
                  </div>
                </Tab.Panel>
                <Tab.Panel>
                  {/* DPoP Faults Tab */}
                  <div className="mt-4">
                    <DpopFaultInjector />
                  </div>
                </Tab.Panel>
              </Tab.Panels>
            </Tab.Group>
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