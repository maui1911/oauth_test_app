import { useEffect, useState } from 'react';

interface ClientKeysPanelProps {
  /** The externally reachable jwks_uri to register at the authorization server. */
  jwksPublicUrl: string;
}

const ALGORITHMS = ['RS256', 'ES256'] as const;

/**
 * Shows what the authorization server needs to verify our client_assertion: the jwks_uri and, for
 * servers that take an upload instead, the same public keys as downloadable certificates.
 */
export function ClientKeysPanel({ jwksPublicUrl }: ClientKeysPanelProps) {
  const [jwks, setJwks] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetch('/api/jwks')
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      })
      .then((data) => setJwks(JSON.stringify(data, null, 2)))
      .catch((err: unknown) =>
        setError(`Could not load /api/jwks (is the proxy running?): ${err instanceof Error ? err.message : String(err)}`)
      );
  }, []);

  const copyJwksUri = async () => {
    try {
      await navigator.clipboard.writeText(jwksPublicUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard unavailable (insecure context); the URL is still visible to copy by hand.
    }
  };

  return (
    <div className="mb-6 rounded-md border border-gray-200 bg-gray-50 p-4">
      <h2 className="text-lg font-medium text-gray-900 mb-2">Client keys (private_key_jwt)</h2>
      <p className="text-sm text-gray-600 mb-3">
        Register either the jwks_uri or one of the certificates at the authorization server. The
        assertion header carries <span className="font-mono">kid</span>, <span className="font-mono">x5t</span> and{' '}
        <span className="font-mono">x5t#S256</span>, so both ways of registering work.
      </p>
      <div className="flex items-center gap-2 mb-3">
        <span className="text-sm font-medium text-gray-500">jwks_uri</span>
        <code className="text-sm text-gray-900 break-all">{jwksPublicUrl}</code>
        <button
          onClick={copyJwksUri}
          className="shrink-0 rounded-md bg-blue-600 px-3 py-1 text-xs text-white hover:bg-blue-700"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <span className="text-sm font-medium text-gray-500">Certificates</span>
        {ALGORITHMS.map((alg) => (
          <span key={alg} className="flex gap-1">
            <a
              href={`/api/client-cert/${alg}.cer`}
              download
              className="rounded-md bg-gray-600 px-3 py-1 text-xs text-white hover:bg-gray-700"
            >
              {alg} .cer (DER)
            </a>
            <a
              href={`/api/client-cert/${alg}.pem`}
              download
              className="rounded-md bg-gray-600 px-3 py-1 text-xs text-white hover:bg-gray-700"
            >
              {alg} .pem
            </a>
          </span>
        ))}
      </div>
      {error && <p className="text-sm text-red-700">{error}</p>}
      {jwks && (
        <details>
          <summary className="cursor-pointer text-sm font-medium text-gray-700">JWKS contents</summary>
          <pre className="mt-1 text-xs text-gray-500 bg-white p-2 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-64">
            {jwks}
          </pre>
        </details>
      )}
    </div>
  );
}
