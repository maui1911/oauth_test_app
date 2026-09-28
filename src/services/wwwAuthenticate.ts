/**
 * Reads one auth-param out of a WWW-Authenticate value. The name is matched up to the "=", so
 * looking for `error` does not also hit `error_description`.
 */
export function challengeParam(challenge: string | null | undefined, name: string): string | undefined {
  if (!challenge) {
    return undefined;
  }
  return new RegExp(`(?:^|[\\s,])${name}="([^"]*)"`).exec(challenge)?.[1];
}
