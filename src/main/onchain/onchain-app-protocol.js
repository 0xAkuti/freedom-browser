/**
 * ERC-4804/6860 web3 protocol with ERC-6821 names and ERC-8244 discovery.
 *
 * Root URLs prefer the read-only `html()` interface (`0x33c34ac3`). Other
 * URLs translate paths and queries into read-only EVM calls. Name URLs
 * resolve before executing code under a contract-and-chain-scoped origin.
 * Network access from the document is denied by response policy; Ethereum
 * reads and signing continue through Freedom's existing EIP-1193 bridge.
 */

const crypto = require('crypto');
const path = require('path');
const { pathToFileURL } = require('url');
const { ethers } = require('ethers');
const log = require('../logger');
const chainData = require('../networks/chain-data-router');
const networkRegistry = require('../networks/network-registry');
const { getPermissionKey, parseWeb3Url } = require('../../shared/origin-utils');
const { resolveWeb3Name, weakestTrust } = require('./web3-name-resolver');
const { RESOLVE_MODE_SELECTOR, buildWeb3Call, decodeWeb3Result, resolveMode } = require('./web3-call');
const { registerWebRequestHandler } = require('../webrequest-dispatcher');
const { createTaskWorkerHost, TaskWorkerUnavailable, TaskWorkerTimeout } = require('../task-worker-host');
const {
  MAX_HTML_BYTES,
  assertHtmlResultSize,
  decodeHtmlDocument,
  decodeHtmlResult,
} = require('./onchain-html');
const {
  runWithPrivateLogContext,
  redactUrlForLog,
  redactForLog,
} = require('../private/private-log-context');

const HTML_SELECTOR = '0x33c34ac3';
const PROVENANCE_HEADER = 'X-Freedom-Onchain-App-Provenance';
const GATE_HEADER = 'X-Freedom-Onchain-App-Gate';
const APPROVAL_HEADER = 'X-Freedom-Onchain-App-Approval';
const DEFAULT_CHAIN_ID = 1;
const REQUEST_TIMEOUT_MS = 30_000;
const PENDING_DOCUMENT_TTL_MS = 5 * 60 * 1000;
const MAX_PENDING_DOCUMENTS = 8;
const MAX_APPROVED_DOCUMENTS = 1024;
const ETHEREUM_ADDRESS_RE = /^0x[0-9a-f]{40}$/i;
// Decoding an 8 MiB document takes ~0.7 s (hex check, ABI decode, pure-JS
// keccak), so it runs in a worker; see onchain-html.js. The input is bounded
// by MAX_HTML_BYTES, so a decode still running after this is a broken worker,
// not a big document.
const DECODE_TIMEOUT_MS = 15_000;
const htmlWorker = createTaskWorkerHost({
  name: 'OnchainHtml',
  workerPath: path.join(__dirname, 'onchain-html-worker.js'),
  timeoutMs: DECODE_TIMEOUT_MS,
  resourceLimits: { maxOldGenerationSizeMb: 256, maxYoungGenerationSizeMb: 32 },
});
const provenanceByWebContentsId = new Map();
const observedWebContentsIds = new Set();
const ONCHAIN_INTERSTITIAL_URL = pathToFileURL(
  path.join(__dirname, '../../renderer/pages/onchain-unverified.html')
).toString();

const ONCHAIN_APP_CSP = [
  "default-src 'none'",
  "script-src 'unsafe-inline' blob:",
  "style-src 'unsafe-inline'",
  'img-src data: blob:',
  'font-src data:',
  'media-src data: blob:',
  "connect-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "worker-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  // Preserve the contract+chain `web3:` origin for app-local storage while
  // keeping navigation/popups and every unlisted sandbox capability denied.
  // This cannot expose host storage: every contract and chain has a distinct
  // custom-scheme origin, inside a context-isolated webview.
  'sandbox allow-scripts allow-same-origin allow-forms allow-modals allow-downloads',
].join('; ');

const ONCHAIN_APP_PERMISSIONS_POLICY = [
  'accelerometer=()',
  'camera=()',
  'display-capture=()',
  'geolocation=()',
  'gyroscope=()',
  'microphone=()',
  'midi=()',
  'payment=()',
  'publickey-credentials-create=()',
  'publickey-credentials-get=()',
  'usb=()',
].join(', ');

function parseOnchainAppUrl(input) {
  const parsed = parseWeb3Url(input);
  if (!parsed) return null;
  return {
    address: parsed.address ? ethers.getAddress(parsed.address) : null,
    ...(parsed.name ? { name: parsed.name } : {}),
    ...(parsed.from ? { from: parsed.from } : {}),
    chainId: parsed.chainId,
  };
}

function textResponse(status, message, extraHeaders = {}) {
  return new Response(message, {
    status,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extraHeaders,
    },
  });
}

function buildOnchainProvenance(htmlHash, app, chainResult = {}) {
  const network = networkRegistry.getNetwork(app.chainId);
  return {
    version: 1,
    chainId: app.chainId,
    network: network?.name || `Chain ${app.chainId}`,
    contract: app.address,
    htmlHash,
    trust: chainResult.trust || {
      level: chainResult.verified === true ? 'verified' : 'unverified',
      method: chainResult.source || 'direct',
      block: null,
      agreed: [],
      dissented: [],
      queried: [],
    },
  };
}

function documentApprovalKey(app, htmlHash) {
  return `${app.chainId}:${app.address.toLowerCase()}:${htmlHash.toLowerCase()}`;
}

function createOnchainAppTrustState({
  now = () => Date.now(),
  createToken = () => crypto.randomBytes(32).toString('base64url'),
} = {}) {
  const pendingDocuments = new Map();
  const approvedDocuments = new Set();

  const prunePending = () => {
    const currentTime = now();
    for (const [token, candidate] of pendingDocuments) {
      if (candidate.expiresAt <= currentTime) pendingDocuments.delete(token);
    }
    while (pendingDocuments.size >= MAX_PENDING_DOCUMENTS) {
      pendingDocuments.delete(pendingDocuments.keys().next().value);
    }
  };

  return {
    isApproved(app, htmlHash) {
      return approvedDocuments.has(documentApprovalKey(app, htmlHash));
    },

    stage(candidate) {
      prunePending();
      const token = createToken();
      if (!/^[A-Za-z0-9_-]{43}$/.test(token) || pendingDocuments.has(token)) {
        throw new Error('failed to create a unique onchain app approval token');
      }
      pendingDocuments.set(token, {
        ...candidate,
        expiresAt: now() + PENDING_DOCUMENT_TTL_MS,
      });
      return token;
    },

    consume(token, requestUrl, app) {
      if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
      const candidate = pendingDocuments.get(token);
      pendingDocuments.delete(token);
      if (
        !candidate ||
        candidate.expiresAt <= now() ||
        candidate.requestUrl !== documentUrl(requestUrl) ||
        (candidate.requestApp || candidate.app).chainId !== app.chainId ||
        (candidate.requestApp || candidate.app).address !== app.address ||
        (candidate.requestApp || candidate.app).name !== app.name
      ) {
        return null;
      }

      const approvalKey = documentApprovalKey(candidate.app, candidate.provenance.htmlHash);
      if (!approvedDocuments.has(approvalKey) && approvedDocuments.size >= MAX_APPROVED_DOCUMENTS) {
        approvedDocuments.delete(approvedDocuments.values().next().value);
      }
      approvedDocuments.add(approvalKey);
      return candidate;
    },
  };
}

const standaloneTrustState = createOnchainAppTrustState();

function encodeOnchainProvenance(provenance) {
  return Buffer.from(JSON.stringify(provenance), 'utf8').toString('base64url');
}

function decodeOnchainProvenance(value) {
  if (typeof value !== 'string' || !value || value.length > 16_384) return null;
  try {
    const provenance = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
    if (
      provenance?.version !== 1 ||
      !Number.isSafeInteger(provenance.chainId) ||
      provenance.chainId <= 0 ||
      !ETHEREUM_ADDRESS_RE.test(provenance.contract) ||
      !/^0x[0-9a-f]{64}$/i.test(provenance.htmlHash) ||
      !provenance.trust?.level
    ) {
      return null;
    }
    return provenance;
  } catch {
    return null;
  }
}

function htmlResponse(html, app, provenance, chainResult, method, contentType = 'text/html; charset=utf-8') {
  const headers = {
    ...(contentType ? { 'Content-Type': contentType } : {}),
    'Cache-Control': 'no-store',
    'Content-Security-Policy': ONCHAIN_APP_CSP,
    'Permissions-Policy': ONCHAIN_APP_PERMISSIONS_POLICY,
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-Freedom-Onchain-App-Chain-Id': String(app.chainId),
    'X-Freedom-Onchain-App-Contract': app.address,
    'X-Freedom-Onchain-App-Source': chainResult.source || 'unknown',
    'X-Freedom-Onchain-App-Verified': chainResult.verified === true ? 'true' : 'false',
    [PROVENANCE_HEADER]: encodeOnchainProvenance(provenance),
  };
  return new Response(method === 'HEAD' ? null : html, { status: 200, headers });
}

function requestHeader(request, name) {
  if (request?.headers?.get) return request.headers.get(name);
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(request?.headers || {})) {
    if (key.toLowerCase() === wanted) return Array.isArray(value) ? value[0] : value;
  }
  return null;
}

function trustEndpoint(trust = {}) {
  return trust.agreed?.[0] || trust.prover || trust.queried?.[0] || trust.method || 'unknown';
}

function hasTrustConflict(trust = {}) {
  return Array.isArray(trust.dissented) && trust.dissented.length > 0;
}

function buildOnchainInterstitialUrl({ app, provenance, requestUrl, token = null }) {
  const url = new URL(ONCHAIN_INTERSTITIAL_URL);
  const trust = provenance.trust || {};
  url.searchParams.set('target', documentUrl(requestUrl));
  url.searchParams.set('network', provenance.network);
  url.searchParams.set('chain', String(app.chainId));
  url.searchParams.set('contract', app.address);
  url.searchParams.set('hash', provenance.htmlHash);
  url.searchParams.set('source', trustEndpoint(trust));
  if (token) url.searchParams.set('token', token);
  if (hasTrustConflict(trust)) {
    url.searchParams.set('conflict', '1');
    url.searchParams.set('dissented', trust.dissented.join(', '));
  }
  return url.toString();
}

function encodeGateUrl(location) {
  return Buffer.from(location, 'utf8').toString('base64url');
}

function decodeGateUrl(value, requestUrl) {
  if (typeof value !== 'string' || !value || value.length > 16_384) return null;
  try {
    const location = Buffer.from(value, 'base64url').toString('utf8');
    const url = new URL(location);
    const expected = new URL(ONCHAIN_INTERSTITIAL_URL);
    if (url.protocol !== 'file:' || url.pathname !== expected.pathname) return null;

    const target = url.searchParams.get('target');
    const app = parseOnchainAppUrl(target);
    if (!app || documentUrl(target) !== documentUrl(requestUrl)) return null;
    if (!app.name && url.searchParams.get('chain') !== String(app.chainId)) return null;
    if (!app.name && url.searchParams.get('contract') !== app.address) return null;
    if (!ETHEREUM_ADDRESS_RE.test(url.searchParams.get('contract') || '')) return null;
    const resolvedChain = Number(url.searchParams.get('chain'));
    if (!Number.isSafeInteger(resolvedChain) || resolvedChain <= 0) return null;
    if (!/^0x[0-9a-f]{64}$/i.test(url.searchParams.get('hash') || '')) return null;

    const conflict = url.searchParams.get('conflict') === '1';
    const token = url.searchParams.get('token') || '';
    if (!conflict && !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
    if (conflict && token) return null;
    return url.toString();
  } catch {
    return null;
  }
}

function interstitialResponse(location) {
  return new Response('Freedom blocked unverified onchain application code.', {
    status: 451,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      [GATE_HEADER]: encodeGateUrl(location),
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

function abortError(message) {
  const error = new Error(message);
  error.name = 'AbortError';
  return error;
}

async function withDeadline(promise, timeoutMs, signal) {
  let timeoutId;
  let abortHandler;
  const deadline = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(abortError('onchain app request timed out')), timeoutMs);
    if (signal) {
      abortHandler = () => reject(abortError('onchain app request aborted'));
      if (signal.aborted) abortHandler();
      else signal.addEventListener('abort', abortHandler, { once: true });
    }
  });
  try {
    return await Promise.race([promise, deadline]);
  } finally {
    clearTimeout(timeoutId);
    if (signal && abortHandler) signal.removeEventListener('abort', abortHandler);
  }
}

// `{ html, htmlHash }` for an html() result, decoded and hashed off the main
// thread. Done here instead only when the worker cannot start, or crashes
// while on this very document (see task-worker-host.js) — then this one
// document costs the main thread its ~1 s, as it did before the worker.
async function decodeHtmlInWorker(result, signal, responseOptions) {
  // O(1), before an oversized result is copied to the worker at all.
  assertHtmlResultSize(result);
  try {
    return await htmlWorker.run('decode', { result, responseOptions }, { signal });
  } catch (error) {
    if (!(error instanceof TaskWorkerUnavailable)) throw error;
    if (signal?.aborted) throw abortError('onchain app request aborted');
    return responseOptions ? decodeWeb3Result(result, responseOptions) : decodeHtmlDocument(result);
  }
}

// The decode shares the request's deadline and cancellation with the chain
// read: a navigation that was aborted, or has used up its budget, stops
// holding (or waiting for) the single decode worker.
async function decodeWithinDeadline(result, remainingMs, signal, responseOptions) {
  const controller = new AbortController();
  try {
    return await withDeadline(
      decodeHtmlInWorker(result, controller.signal, responseOptions),
      Math.max(0, remainingMs),
      signal
    );
  } finally {
    // A no-op once the decode has settled; otherwise drops it from the queue
    // or stops the worker that is on it.
    controller.abort();
  }
}

// A bare name's address is only a website when it implements ERC-8244.
// Reuse the document worker and the navigation deadline without retaining
// the HTML in the name cache or executing any of it during discovery.
async function probeOnchainHtml(address, chainId = DEFAULT_CHAIN_ID, {
  chainRequest = chainData.request,
  timeoutMs = REQUEST_TIMEOUT_MS,
  signal,
} = {}) {
  const startedAt = Date.now();
  const controller = new AbortController();
  try {
    signal?.throwIfAborted();
    const chainResult = await withDeadline(Promise.resolve().then(() => chainRequest(
      chainId,
      'eth_call',
      [{ to: ethers.getAddress(address), data: HTML_SELECTOR }, 'latest'],
      {
        includeTrust: true,
        signal: controller.signal,
        routingContext: { origin: getPermissionKey(`web3://${address}:${chainId}/`) },
      }
    )), timeoutMs, signal);
    const trust = chainResult?.trust || {
      level: chainResult?.verified === true ? 'verified' : 'unverified',
      method: chainResult?.source || 'direct',
    };
    try {
      const { html } = await decodeWithinDeadline(
        chainResult?.result, timeoutMs - (Date.now() - startedAt), signal
      );
      return { supported: html.length > 0, trust };
    } catch (error) {
      if (error?.name === 'AbortError' || error?.code === 'ONCHAIN_APP_TOO_LARGE' ||
          error instanceof TaskWorkerTimeout) throw error;
      return { supported: false, trust };
    }
  } catch (error) {
    if (error?.code === 'CALL_EXCEPTION') return { supported: false, trust: { level: 'unverified' } };
    throw error;
  } finally {
    controller.abort();
  }
}

async function handleOnchainAppRequest(
  request,
  {
    chainRequest = chainData.request,
    timeoutMs = REQUEST_TIMEOUT_MS,
    trustState = standaloneTrustState,
    resolveName = resolveWeb3Name,
  } = {}
) {
  const method = (request.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') {
    return textResponse(405, 'onchain applications only support GET and HEAD', {
      Allow: 'GET, HEAD',
    });
  }

  const requestApp = parseOnchainAppUrl(request.url);
  if (!requestApp) {
    return textResponse(
      400,
      'invalid web3 URL; expected web3://<contract-or-name>:<chainId>/'
    );
  }

  if (method === 'GET') {
    const approvalToken = requestHeader(request, APPROVAL_HEADER);
    const approvedCandidate = trustState.consume(approvalToken, request.url, requestApp);
    if (approvedCandidate) {
      if (approvedCandidate.redirectUrl) return redirectResponse(approvedCandidate.redirectUrl);
      return htmlResponse(
        approvedCandidate.html,
        approvedCandidate.app,
        approvedCandidate.provenance,
        approvedCandidate.chainResult,
        method,
        approvedCandidate.contentType
      );
    }
  }

  const startedAt = Date.now();
  try {
    let app = requestApp;
    let redirectUrl = null;
    let nameTrust = null;
    const parsed = parseWeb3Url(request.url);
    const withinDeadline = (promise) => withDeadline(
      promise, Math.max(0, timeoutMs - (Date.now() - startedAt)), request.signal
    );
    if (app.name) {
      const resolved = await withinDeadline(resolveName(app.name, app.chainId));
      app = { address: resolved.address, chainId: resolved.chainId, ...(app.from ? { from: app.from } : {}) };
      nameTrust = resolved.trust || { level: 'unverified' };
      const sender = app.from ? `${app.from}@` : '';
      redirectUrl = `web3://${sender}${app.address.toLowerCase()}.eip155-${app.chainId}${parsed.path}${parsed.query}${parsed.fragment}`;
      // Navigation reaches the contract origin before any app code executes.
      // This pins storage and the wallet provider to the resolved chain even
      // when contentcontract changes it via an ERC-3770 prefix.
      if (isTrusted(nameTrust)) return redirectResponse(redirectUrl);
    }
    const call = (data, explicitSender = false) => {
      const transaction = {
        to: app.address,
        data,
        ...(app.from || explicitSender ? { from: app.from || ethers.ZeroAddress } : {}),
      };
      return withinDeadline(Promise.resolve().then(() => chainRequest(
          app.chainId,
          'eth_call',
          [transaction, 'latest'],
          {
            includeTrust: true,
            // The document fetch is the first app-driven read. Give it the
            // same per-origin latency budget and adaptive fall-through as the
            // EIP-1193 calls the loaded document will make afterwards.
            routingContext: { origin: getPermissionKey(request.url) },
          }
        )));
    };
    const decode = (result, options) => decodeWithinDeadline(
      result, timeoutMs - (Date.now() - startedAt), request.signal, options
    );
    let chainResult;
    let decoded;
    // ERC-8244 discovery at the root remains the preferred single-call path.
    // Explicit method URLs always retain ERC-6860 semantics.
    if (parsed.path === '/' && !parsed.query) {
      try {
        chainResult = await call(HTML_SELECTOR);
        decoded = await decode(chainResult?.result);
        if (!decoded.html) decoded = null;
      } catch (error) {
        if (error?.name === 'AbortError' || error?.code === 'ONCHAIN_APP_TOO_LARGE') throw error;
      }
    }
    let argumentTrust = null;
    if (!decoded) {
      const triedHtml = parsed.path === '/' && !parsed.query;
      let mode = 'auto';
      try {
        let modeResult;
        try {
          modeResult = await call(RESOLVE_MODE_SELECTOR, true);
        } catch (error) {
          if (error?.name === 'AbortError') throw error;
        }
        mode = resolveMode(modeResult?.result);
        const options = await withinDeadline(buildWeb3Call(parsed, mode, async (name) => {
          const resolved = await resolveName(name, parsed.chainId, { contentContract: false });
          argumentTrust = weakestTrust(argumentTrust, resolved.trust || { level: 'unverified' });
          return resolved.address;
        }));
        chainResult = await call(options.data, true);
        chainResult = {
          ...chainResult,
          trust: weakestTrust(
            chainResult?.trust || { level: chainResult?.verified ? 'verified' : 'unverified' },
            modeResult?.trust,
            argumentTrust
          ),
        };
        decoded = await decode(chainResult?.result, options);
      } catch (error) {
        if (
          triedHtml || mode === 'manual' ||
          error?.name === 'AbortError' || error?.code === 'ONCHAIN_APP_TOO_LARGE'
        ) {
          throw error;
        }
        // A path that names no contract method is an ERC-8244 client route.
        // A reloaded deep link keeps opening the app's document.
        chainResult = await call(HTML_SELECTOR);
        decoded = await decode(chainResult?.result);
        if (!decoded.html) throw error;
      }
    }
    const { html, htmlHash } = decoded;
    const contentType = Object.hasOwn(decoded, 'contentType')
      ? decoded.contentType || null : 'text/html; charset=utf-8';
    if (nameTrust) chainResult = { ...chainResult, trust: weakestTrust(chainResult?.trust, nameTrust) };
    const provenance = buildOnchainProvenance(htmlHash, app, chainResult || {});
    const trusted = isTrusted(provenance.trust);
    if (method === 'GET' && !trusted && !trustState.isApproved(app, provenance.htmlHash)) {
      const conflict = hasTrustConflict(provenance.trust);
      const token = conflict
        ? null
        : trustState.stage({
            app,
            requestApp,
            redirectUrl,
            contentType,
            chainResult: chainResult || {},
            html,
            provenance,
            requestUrl: documentUrl(request.url),
          });
      return interstitialResponse(
        buildOnchainInterstitialUrl({ app, provenance, requestUrl: request.url, token })
      );
    }
    if (redirectUrl) return redirectResponse(redirectUrl);
    return htmlResponse(html, app, provenance, chainResult || {}, method, contentType);
  } catch (error) {
    const loggedUrl = redactUrlForLog(request.url);
    if (error?.code === 'ONCHAIN_APP_TOO_LARGE') {
      log.warn(`[onchain-app] rejected oversized html() response for ${loggedUrl}`);
      return textResponse(413, error.message);
    }
    if (error?.name === 'AbortError') {
      log.warn(`[onchain-app] timed out loading ${loggedUrl}`);
      return textResponse(504, 'onchain application read timed out');
    }
    log.warn(`[onchain-app] failed to load ${loggedUrl}: ${redactForLog(error?.message || error)}`);
    return textResponse(
      502,
      'the name or contract did not return valid web3 content on this chain'
    );
  }
}

function isTrusted(trust) {
  return trust?.level === 'verified' || trust?.level === 'user-configured';
}

function redirectResponse(location) {
  return new Response(null, { status: 302, headers: { Location: location, 'Cache-Control': 'no-store' } });
}

function responseHeader(responseHeaders, name) {
  const wanted = name.toLowerCase();
  for (const [key, values] of Object.entries(responseHeaders || {})) {
    if (key.toLowerCase() !== wanted) continue;
    return Array.isArray(values) ? values[0] : values;
  }
  return null;
}

function documentUrl(value) {
  try {
    const url = new URL(value);
    url.hash = '';
    return url.toString();
  } catch {
    return '';
  }
}

// Strip the gate header from a response that is not going to a top-level
// navigation. Returns the remaining headers, or null when there was nothing
// to strip (so the dispatcher chain is left untouched).
function withoutGateHeader(responseHeaders) {
  const wanted = GATE_HEADER.toLowerCase();
  let stripped = false;
  const remaining = {};
  for (const [key, value] of Object.entries(responseHeaders || {})) {
    if (key.toLowerCase() === wanted) {
      stripped = true;
      continue;
    }
    remaining[key] = value;
  }
  return stripped ? remaining : null;
}

function captureOnchainProvenance(details) {
  if (details?.resourceType !== 'mainFrame') {
    // Defence in depth behind guardOnchainAppRequest: the gate header carries
    // the single-use approval token, and Chromium enforces no CORS on a
    // custom-scheme response — so it must never reach a reader that is not
    // Freedom's own top-level navigation, whatever future path served it.
    if (!documentUrl(details?.url).startsWith('web3://')) return null;
    const responseHeaders = withoutGateHeader(details?.responseHeaders);
    return responseHeaders ? { responseHeaders } : null;
  }
  const contents = details.webContents;
  const previous = provenanceByWebContentsId.get(contents?.id);
  provenanceByWebContentsId.delete(contents?.id);
  if (!documentUrl(details.url).startsWith('web3://')) return null;
  if (contents?.id && !observedWebContentsIds.has(contents.id)) {
    observedWebContentsIds.add(contents.id);
    contents.once?.('destroyed', () => {
      provenanceByWebContentsId.delete(contents.id);
      observedWebContentsIds.delete(contents.id);
    });
  }
  // Preserve only a redirect issued by our name resolver, for this guest and
  // this exact destination. The renderer reuses it for chrome display only;
  // storage and wallet identity continue to use the actual contract origin.
  const namedSource = parseWeb3Url(details.url);
  const redirectTarget = parseWeb3Url(responseHeader(details.responseHeaders, 'Location'));
  if (details.statusCode === 302 && namedSource?.name && redirectTarget?.address && contents?.id) {
    provenanceByWebContentsId.set(contents.id, {
      url: documentUrl(redirectTarget.url),
      pendingNameUrl: namedSource.displayUrl,
      provenance: null,
    });
    return null;
  }
  const gateUrl = decodeGateUrl(responseHeader(details.responseHeaders, GATE_HEADER), details.url);
  if (gateUrl && details.statusCode === 451) {
    const contents = details.webContents;
    if (contents) {
      // Leave the webRequest callback stack before replacing the blocked
      // response. Starting the file navigation synchronously from
      // onHeadersReceived makes Chromium abort the replacement itself.
      setImmediate(() => {
        if (contents.isDestroyed?.()) return;
        try {
          Promise.resolve(contents.loadURL?.(gateUrl)).catch((error) => {
            log.warn(`[onchain-app] failed to open trust interstitial: ${error?.message || error}`);
          });
        } catch (error) {
          log.warn(`[onchain-app] failed to open trust interstitial: ${error?.message || error}`);
        }
      });
    }
    return null;
  }
  if (details.statusCode !== 200) return null;
  const encoded = responseHeader(details.responseHeaders, PROVENANCE_HEADER);
  const provenance = decodeOnchainProvenance(encoded);
  if (!provenance || !contents?.id) return null;

  delete provenance.nameUrl;
  if (previous?.pendingNameUrl && previous.url === documentUrl(details.url)) {
    provenance.nameUrl = previous.pendingNameUrl;
  }

  provenanceByWebContentsId.set(contents.id, {
    url: documentUrl(details.url),
    provenance,
  });
  return null;
}

/**
 * onBeforeRequest guard: drop every `web3:` request that is not a top-level
 * navigation.
 *
 * An onchain app is only ever a top-level document — `frame-ancestors 'none'`
 * plus `X-Frame-Options: DENY` say so, and its own CSP denies it any
 * subresource fetch — so nothing legitimate loads this scheme as a
 * subresource. Web content could, though: nothing in a custom-scheme request
 * reaching `protocol.handle` is trustworthy (Chromium sends no `Origin`
 * header for one and does not enforce CORS on the response either), so a
 * plain `fetch('web3://<app>.eip155-1/')` from a hostile page used to read
 * the 451 gate response in full — including the single-use approval token —
 * replay it with the approval header, and silently pre-approve unverified
 * app code for the whole session before the user ever saw the interstitial.
 * The same reachability let any page grind the staged-document FIFO and evict
 * a real user's pending token.
 *
 * The initiating request's resource type, taken from the network layer before
 * the handler runs, is the only value the main process can trust here. Fails
 * closed: a request Chromium cannot attribute to a main frame is cancelled.
 */
function guardOnchainAppRequest(details) {
  if (!/^web3:/i.test(details?.url || '')) return null;
  if (details.resourceType === 'mainFrame') return null;
  log.warn('[onchain-app] Blocked a web3: request that is not a top-level navigation');
  return { cancel: true };
}

function installOnchainProvenanceCapture() {
  registerWebRequestHandler('onBeforeRequest', 'onchain-app-guard', guardOnchainAppRequest, {
    failClosed: true,
  });
  registerWebRequestHandler('onHeadersReceived', 'onchain-provenance', captureOnchainProvenance);
}

function registerOnchainProvenanceIpc() {
  const { ipcMain, webContents } = require('electron');
  const IPC = require('../../shared/ipc-channels');
  ipcMain.handle(IPC.ONCHAIN_APP_GET_PROVENANCE, (event, payload = {}) => {
    const webContentsId = Number(payload.webContentsId);
    if (!Number.isSafeInteger(webContentsId) || webContentsId <= 0) return null;
    const guest = webContents.fromId(webContentsId);
    if (!guest || guest.hostWebContents?.id !== event.sender.id) return null;
    const record = provenanceByWebContentsId.get(webContentsId);
    if (!record || record.url !== documentUrl(payload.url)) return null;
    return record.provenance;
  });
}

function registerOnchainAppProtocol(targetSession, { privatePartition = null } = {}) {
  if (!targetSession?.protocol?.handle) {
    log.warn('[onchain-app] session.protocol.handle unavailable — skipping');
    return;
  }
  const isPrivate = !!privatePartition;
  const trustState = createOnchainAppTrustState();
  try {
    targetSession.protocol.handle('web3', (request) =>
      runWithPrivateLogContext(isPrivate, () => handleOnchainAppRequest(request, { trustState }))
    );
    log.info('[onchain-app] web3: handler registered');
  } catch (error) {
    log.error('[onchain-app] failed to register web3: handler:', error);
  }
}

module.exports = {
  APPROVAL_HEADER,
  DEFAULT_CHAIN_ID,
  GATE_HEADER,
  HTML_SELECTOR,
  MAX_HTML_BYTES,
  ONCHAIN_APP_CSP,
  ONCHAIN_APP_PERMISSIONS_POLICY,
  REQUEST_TIMEOUT_MS,
  PROVENANCE_HEADER,
  buildOnchainProvenance,
  buildOnchainInterstitialUrl,
  captureOnchainProvenance,
  decodeOnchainProvenance,
  decodeHtmlInWorker,
  decodeHtmlResult,
  encodeOnchainProvenance,
  htmlWorker,
  guardOnchainAppRequest,
  handleOnchainAppRequest,
  installOnchainProvenanceCapture,
  parseOnchainAppUrl,
  probeOnchainHtml,
  createOnchainAppTrustState,
  registerOnchainProvenanceIpc,
  registerOnchainAppProtocol,
};
