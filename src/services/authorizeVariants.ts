// Deliberately malformed authorize requests. Once client_id and redirect_uri check out, the server
// reports errors by redirecting back to the client, so each variant is judged at the callback.

export type AuthorizeVariantKey =
  | 'none'
  | 'code-challenge-missing'
  | 'code-challenge-method-missing'
  | 'response-type-token'
  | 'response-type-missing'
  | 'state-duplicate'
  | 'redirect-uri-host-case'
  | 'redirect-uri-path-case';

export interface AuthorizeVariant {
  key: AuthorizeVariantKey;
  label: string;
  /** What the server should answer, shown before the request and again with the result. */
  expected: string;
  /** Set when a code coming back means the server accepted something it should have refused. */
  expectsRejection: boolean;
}

export const AUTHORIZE_VARIANTS: AuthorizeVariant[] = [
  {
    key: 'none',
    label: 'Valid request',
    expected: 'A redirect back with a code and the state.',
    expectsRejection: false,
  },
  {
    key: 'code-challenge-missing',
    label: 'code_challenge omitted',
    expected: 'A redirect back with error=invalid_request and the state.',
    expectsRejection: true,
  },
  {
    key: 'code-challenge-method-missing',
    label: 'code_challenge_method omitted',
    expected:
      'A redirect back with error=invalid_request, "Transform algorithm not supported" and the state (absent means plain).',
    expectsRejection: true,
  },
  {
    key: 'response-type-token',
    label: 'response_type=token',
    expected: 'A redirect back with error=unsupported_response_type and the state.',
    expectsRejection: true,
  },
  {
    key: 'response-type-missing',
    label: 'response_type omitted',
    expected: 'A redirect back with error=invalid_request and the state.',
    expectsRejection: true,
  },
  {
    key: 'state-duplicate',
    label: 'state sent twice',
    expected: 'A redirect back with error=invalid_request and no state.',
    expectsRejection: true,
  },
  {
    key: 'redirect-uri-host-case',
    label: 'redirect_uri host in capitals',
    expected:
      'A redirect back with a code: scheme and host compare case-insensitively. The code exchange repeats the same redirect_uri.',
    expectsRejection: false,
  },
  {
    key: 'redirect-uri-path-case',
    label: 'redirect_uri path in capitals',
    expected:
      'No redirect back: the path must match exactly, so the server answers with a JSON 400 of its own.',
    expectsRejection: true,
  },
];

export function findAuthorizeVariant(key: string | null): AuthorizeVariant {
  return AUTHORIZE_VARIANTS.find((variant) => variant.key === key) ?? AUTHORIZE_VARIANTS[0];
}

export function applyAuthorizeVariant(params: URLSearchParams, key: AuthorizeVariantKey): void {
  switch (key) {
    case 'code-challenge-missing':
      params.delete('code_challenge');
      break;
    case 'code-challenge-method-missing':
      params.delete('code_challenge_method');
      break;
    case 'response-type-token':
      params.set('response_type', 'token');
      break;
    case 'response-type-missing':
      params.delete('response_type');
      break;
    case 'state-duplicate':
      params.append('state', params.get('state') ?? '');
      break;
    case 'redirect-uri-host-case':
    case 'redirect-uri-path-case': {
      const uri = new URL(params.get('redirect_uri') ?? '');
      // URL lowercases the host on assignment, so the capitals have to go in as text.
      const rewritten =
        key === 'redirect-uri-host-case'
          ? `${uri.protocol}//${uri.host.toUpperCase()}${uri.pathname}${uri.search}`
          : `${uri.origin}${uri.pathname.toUpperCase()}${uri.search}`;
      params.set('redirect_uri', rewritten);
      break;
    }
  }
}
