const FORWARDED_INIT_KEYS = [
  'cache',
  'credentials',
  'integrity',
  'keepalive',
  'mode',
  'redirect',
  'referrer',
  'referrerPolicy',
  'signal',
] as const;

/**
 * Extract the fetch options that must survive request re-construction
 * (e.g. credentials for cross-origin cookies, signal for aborts).
 *
 * Works on both Request instances and plain RequestInit objects.
 */
export function forwardedRequestInit(source: Request | RequestInit | undefined): RequestInit {
  const forwarded: RequestInit = {};
  if (!source) {
    return forwarded;
  }

  const record = source as unknown as Record<string, unknown>;
  const target = forwarded as unknown as Record<string, unknown>;
  for (const key of FORWARDED_INIT_KEYS) {
    const value = record[key];
    if (value !== undefined) {
      target[key] = value;
    }
  }

  // 'navigate' is a browser-internal mode that the Request constructor rejects.
  if (forwarded.mode === 'navigate') {
    delete forwarded.mode;
  }

  return forwarded;
}
