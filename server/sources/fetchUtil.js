const USER_AGENT = "siren-threat-console/1.0 (+https://github.com/)";

/**
 * fetch() with a timeout and a descriptive error on non-2xx responses.
 */
export async function fetchWithTimeout(url, { timeoutMs = 20000, headers = {}, ...opts } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": USER_AGENT, ...headers },
      ...opts,
    });
    if (!res.ok) {
      throw new Error(`${url} responded ${res.status} ${res.statusText}`);
    }
    return res;
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchJson(url, opts) {
  const res = await fetchWithTimeout(url, opts);
  return res.json();
}

export async function fetchText(url, opts) {
  const res = await fetchWithTimeout(url, opts);
  return res.text();
}
