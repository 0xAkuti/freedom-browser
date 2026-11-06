/**
 * Origin Normalization Utilities
 *
 * Shared origin normalization for permission keying. Used by the main process
 * for swarm-permissions and swarm-provider-ipc. The renderer has an identical
 * copy in src/renderer/lib/origin-utils.js (ES modules cannot require() this
 * file; keep both in sync — see origin-utils.test.js in that directory).
 *
 * Rules (security-critical, locked down in swarm-publishing-research.md):
 *
 *   ens://myapp.eth/#/path  → myapp.eth       (name, lowercased)
 *   myapp.eth/blog          → myapp.eth        (bare name)
 *   bzz://abc123/page       → bzz://abc123     (root ref, path-insensitive)
 *   bzz://myapp.eth/page    → myapp.eth        (transport name-keyed)
 *   ipfs://QmABC/docs       → ipfs://QmABC     (root CID, path-insensitive)
 *   ipfs://myapp.eth/docs   → myapp.eth        (transport name-keyed)
 *   ipns://host/guide       → ipns://host      (hostname, path-insensitive)
 *   ipns://myapp.eth/guide  → myapp.eth        (transport name-keyed)
 *   rad://z123/tree         → rad://z123       (RID, path-insensitive)
 *   web3://0xabc….eip155-1/swap → web3://0xabc… (mainnet app key)
 *   web3://0xabc…:100/swap      → web3://0xabc…:100 (chain-scoped key)
 *   https://app.example.com → https://app.example.com
 *
 * The name-host carve-out for transport URLs keeps permissions stable across
 * the legacy `ens://` form and the new transport-aware display: a user who
 * granted a permission to `myapp.eth` via `ens://myapp.eth` still has it
 * after the address bar starts displaying the same site as `bzz://myapp.eth`.
 */

/**
 * True when `host` looks like a supported Ethereum name
 * (`.eth`, `.box`, `.wei`, or `.gwei`).
 * Used by the carve-out below and (via the renderer mirror) by every other
 * name-host classifier in the codebase. Centralising the predicate keeps a
 * single source of truth for supported name suffixes.
 *
 * @param {string} host
 * @returns {boolean}
 */
function isEnsHost(host) {
  if (!host || typeof host !== 'string') return false;
  const lower = host.toLowerCase();
  return (
    lower.endsWith('.eth') ||
    lower.endsWith('.box') ||
    lower.endsWith('.wei') ||
    lower.endsWith('.gwei')
  );
}

function isPotentialEnsName(value) {
  return typeof value === 'string' && value.includes('.') &&
    !/[\s/:@?#%\\]/u.test(value) &&
    !Array.from(value).some((c) => c.codePointAt(0) < 32 || c.codePointAt(0) === 127) &&
    value.split('.').every((label) => label.length > 0);
}

function isTezosDomainHost(host) {
  if (!host || typeof host !== 'string') return false;
  const lower = host.toLowerCase();
  return lower.endsWith('.tez') && lower.split('.').every((label) => label.length > 0);
}

function isDwebNameHost(host) {
  return isEnsHost(host) || isTezosDomainHost(host);
}

// URL codec shared with the renderer mirror. Chain IDs belong in the
// hostname internally: Chromium treats :chain as a port and rejects bare
// hexadecimal contract hosts as oversized IPv4 literals.
function parseWeb3Url(input) {
  const raw = typeof input === 'string' ? input.trim() : '';
  if (/[\s\\]/u.test(raw) || Array.from(raw).some((c) => c.codePointAt(0) < 32 || c.codePointAt(0) === 127)) return null;
  const match = raw.match(/^(?:web3|w3):\/\/(?:([0-9a-z]+)@)?([^/?#:]+)(?::([1-9][0-9]*))?([^#]*)(#.*)?$/i);
  if (!match) return null;
  const from = match[1]?.toLowerCase();
  if (from && !/^0x[0-9a-f]{40}$/.test(from)) return null;
  const internal = match[2].match(/^(.+)\.eip155-([1-9][0-9]*)$/i);
  if (internal && match[3]) return null;
  if (!internal && /\.eip155-[^.]*$/i.test(match[2])) return null;
  const chainId = Number(internal?.[2] || match[3] || 1);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) return null;
  let target;
  try {
    target = decodeURIComponent(internal?.[1] || match[2]).toLowerCase();
  } catch {
    return null;
  }
  const address = /^0x[0-9a-f]{40}$/.test(target) ? target : null;
  if (!address && !isPotentialEnsName(target)) return null;
  // A malformed address must not fall through to name resolution.
  if (!address && /^0x[0-9a-f]+$/i.test(target)) return null;
  const suffix = match[4] || '/';
  if (!suffix.startsWith('/') && !suffix.startsWith('?')) return null;
  const pathQuery = suffix.startsWith('/') ? suffix : `/${suffix}`;
  const sender = from ? `${from}@` : '';
  let url;
  try {
    url = new URL(`web3://${sender}${target}.eip155-${chainId}${pathQuery}${match[5] || ''}`);
  } catch {
    return null;
  }
  if (url.username !== (from || '') || url.password || url.port) return null;
  const name = address ? null : url.hostname.replace(/\.eip155-[0-9]+$/, '');
  return {
    address,
    name,
    chainId,
    from,
    path: url.pathname,
    query: url.search,
    fragment: url.hash,
    url: url.toString(),
    displayUrl: `web3://${sender}${name || address}${chainId === 1 ? '' : `:${chainId}`}${url.pathname}${url.search}${url.hash}`,
  };
}

/**
 * Extract the permission key from a display URL.
 * Returns the root content identity, never including paths.
 *
 * @param {string} displayUrl
 * @returns {string|null}
 */
function getPermissionKey(displayUrl) {
  if (!displayUrl) return null;

  const trimmed = displayUrl.trim();
  if (!trimmed) return null;

  // Supported Ethereum name without protocol (e.g., 1inch.eth/path).
  // Split on /, ?, and # so that hash-routed SPAs (`name.eth#/swap`) and
  // share-link queries (`name.eth?ref=...`) collapse to the same key as
  // the canonical bare name.
  if (/^[^/?#\s]+\.(eth|box|wei|gwei|tez)(?:[/?#]|$)/i.test(trimmed)) {
    return trimmed.split(/[/?#]/, 1)[0].toLowerCase();
  }

  // ens:// protocol → extract name (e.g., ens://1inch.eth/#/path → 1inch.eth)
  const ensMatch = trimmed.match(/^ens:\/\/([^/?#]+)/i);
  if (ensMatch) {
    return ensMatch[1].toLowerCase();
  }

  // dweb protocols: ipfs://CID/path → ipfs://CID
  // Name-host carve-out: bzz://name.eth/path → name.eth (same key as the
  // legacy ens://name.eth form, so permissions don't fork across transport
  // and legacy displays of the same site). The host pattern excludes
  // ?, # and / so query/fragment components don't fork the key per route.
  const dwebMatch = trimmed.match(/^(ipfs|bzz|ipns):\/\/([^/?#]+)/i);
  if (dwebMatch) {
    const host = dwebMatch[2];
    if (isDwebNameHost(host)) {
      return host.toLowerCase();
    }
    return `${dwebMatch[1].toLowerCase()}://${host}`;
  }

  // rad:// protocol
  const radMatch = trimmed.match(/^rad:\/\/([^/?#]+)/i);
  if (radMatch) {
    return `rad://${radMatch[1]}`;
  }

  // ERC-8244 application origin. Chain identity is part of the permission
  // boundary: the same 20-byte contract address on another chain is a
  // different app and must never inherit wallet grants.
  const onchain = parseWeb3Url(trimmed);
  if (onchain) {
    const chainSuffix = onchain.chainId === 1 ? '' : `:${onchain.chainId}`;
    return `web3://${onchain.address || onchain.name}${chainSuffix}`;
  }

  // Regular URL (https://host/path → https://host)
  try {
    const url = new URL(trimmed);
    if (url.origin === 'null') {
      return trimmed;
    }
    return url.origin;
  } catch {
    return trimmed;
  }
}

/**
 * Normalize an origin for permission storage lookup.
 * Same logic as getPermissionKey — named for clarity in permission store context.
 *
 * @param {string} origin
 * @returns {string}
 */
function normalizeOrigin(origin) {
  return getPermissionKey(origin) || '';
}

module.exports = { isPotentialEnsName, getPermissionKey, isDwebNameHost, isEnsHost, isTezosDomainHost, normalizeOrigin, parseWeb3Url };
