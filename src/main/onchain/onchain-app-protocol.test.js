jest.mock('electron', () => ({
  ipcMain: { handle: jest.fn() },
  webContents: { fromId: jest.fn() },
}));

jest.mock('../logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

jest.mock('../networks/chain-data-router', () => ({
  request: jest.fn(),
}));

jest.mock('../networks/network-registry', () => ({
  getNetwork: jest.fn((chainId) => ({ name: chainId === 1 ? 'Ethereum' : 'Gnosis Chain' })),
}));

const { ethers } = require('ethers');
const chainData = require('../networks/chain-data-router');
const log = require('../logger');
const {
  APPROVAL_HEADER,
  GATE_HEADER,
  HTML_SELECTOR,
  MAX_HTML_BYTES,
  ONCHAIN_APP_CSP,
  PROVENANCE_HEADER,
  decodeOnchainProvenance,
  createOnchainAppTrustState,
  captureOnchainProvenance,
  guardOnchainAppRequest,
  handleOnchainAppRequest,
  htmlWorker,
  parseOnchainAppUrl,
  probeOnchainHtml,
  registerOnchainAppProtocol,
  registerOnchainProvenanceIpc,
} = require('./onchain-app-protocol');
const { TaskWorkerTimeout } = require('../task-worker-host');

const ADDRESS = '0x00000095643CFfA7D9fae407a84dfCB6406456c6';
const CANONICAL_ADDRESS = ethers.getAddress(ADDRESS);
const ABI = new ethers.Interface(['function html() view returns (string)']);
const appUrl = (chainId = 1, path = '/') =>
  `web3://${ADDRESS.toLowerCase()}.eip155-${chainId}${path}`;

function request(url, method = 'GET', signal = undefined) {
  return { url, method, signal, headers: new Headers() };
}

function encodedHtml(html) {
  return ABI.encodeFunctionResult('html', [html]);
}

function gateUrl(response) {
  return new URL(Buffer.from(response.headers.get(GATE_HEADER), 'base64url').toString('utf8'));
}

describe('parseOnchainAppUrl', () => {
  test('parses the contract and explicit chain', () => {
    expect(parseOnchainAppUrl(appUrl(1, '/swap'))).toEqual({
      address: CANONICAL_ADDRESS,
      chainId: 1,
    });
  });

  test('defaults an omitted chain to Ethereum mainnet', () => {
    expect(parseOnchainAppUrl(`web3://${ADDRESS}/`)).toEqual({
      address: CANONICAL_ADDRESS,
      chainId: 1,
    });
  });

  test.each([
    'https://example.com',
    'web3://not-an-address:1/',
    `web3://${ADDRESS}:0/`,
    `web3://user@${ADDRESS}:1/`,
  ])('rejects malformed authority %s', (url) => {
    expect(parseOnchainAppUrl(url)).toBeNull();
  });
});

describe('handleOnchainAppRequest', () => {
  beforeEach(() => jest.clearAllMocks());

  test('calls ERC-8244 html() and returns the unmodified document', async () => {
    const html = '<!doctype html><title>zSwap</title><script>window.ok = true</script>';
    const chainRequest = jest.fn(async () => ({
      result: encodedHtml(html),
      source: 'myotis',
      verified: true,
      trust: {
        level: 'verified',
        method: 'myotis',
        finality: 'optimistic',
        block: 123,
      },
    }));

    const response = await handleOnchainAppRequest(
      request(appUrl()),
      { chainRequest }
    );

    expect(chainRequest).toHaveBeenCalledWith(
      1,
      'eth_call',
      [{ to: CANONICAL_ADDRESS, data: HTML_SELECTOR }, 'latest'],
      {
        includeTrust: true,
        routingContext: { origin: `web3://${ADDRESS.toLowerCase()}` },
      }
    );
    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe(html);
    expect(response.headers.get('content-type')).toBe('text/html; charset=utf-8');
    expect(response.headers.get('content-security-policy')).toBe(ONCHAIN_APP_CSP);
    expect(response.headers.get('content-security-policy')).toContain("connect-src 'none'");
    expect(response.headers.get('content-security-policy')).toContain('sandbox allow-scripts');
    expect(response.headers.get('x-freedom-onchain-app-chain-id')).toBe('1');
    expect(response.headers.get('x-freedom-onchain-app-contract')).toBe(CANONICAL_ADDRESS);
    expect(response.headers.get('x-freedom-onchain-app-verified')).toBe('true');
    expect(decodeOnchainProvenance(response.headers.get(PROVENANCE_HEADER))).toEqual({
      version: 1,
      chainId: 1,
      network: 'Ethereum',
      contract: CANONICAL_ADDRESS,
      htmlHash: ethers.keccak256(ethers.toUtf8Bytes(html)),
      trust: {
        level: 'verified',
        method: 'myotis',
        finality: 'optimistic',
        block: 123,
      },
    });
  });

  test('uses the canonical html() selector', () => {
    expect(HTML_SELECTOR).toBe(ABI.getFunction('html').selector);
  });

  test('HEAD validates the contract but returns no body', async () => {
    const chainRequest = jest.fn(async () => ({
      result: encodedHtml('<h1>app</h1>'),
      source: 'quorum',
      verified: true,
    }));
    const response = await handleOnchainAppRequest(
      request(appUrl(100), 'HEAD'),
      { chainRequest }
    );
    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe('');
    expect(chainRequest).toHaveBeenCalledWith(
      100,
      'eth_call',
      expect.any(Array),
      {
        includeTrust: true,
        routingContext: { origin: `web3://${ADDRESS.toLowerCase()}:100` },
      }
    );
  });

  test('lets a user-configured RPC serve an app without a warning', async () => {
    const html = '<h1>trusted RPC app</h1>';
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => ({
        result: encodedHtml(html),
        trust: {
          level: 'user-configured',
          method: 'direct',
          agreed: ['node.example'],
          dissented: [],
          queried: ['node.example'],
        },
      })),
      trustState: createOnchainAppTrustState(),
    });

    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe(html);
  });

  test('gates public-RPC HTML, then serves the exact cached bytes after approval', async () => {
    const html = '<h1>unverified app</h1><script>window.executed = true</script>';
    const changedHtml = '<h1>changed app</h1>';
    const trustState = createOnchainAppTrustState({
      createToken: () => 'a'.repeat(43),
    });
    const chainRequest = jest
      .fn()
      .mockResolvedValueOnce({
        result: encodedHtml(html),
        trust: {
          level: 'unverified',
          method: 'direct',
          agreed: ['rpc.example'],
          dissented: [],
          queried: ['rpc.example'],
        },
      })
      .mockResolvedValueOnce({
        result: encodedHtml(html),
        trust: {
          level: 'unverified',
          method: 'direct',
          agreed: ['rpc.example'],
          dissented: [],
          queried: ['rpc.example'],
        },
      })
      .mockResolvedValueOnce({
        result: encodedHtml(changedHtml),
        trust: {
          level: 'unverified',
          method: 'direct',
          agreed: ['rpc.example'],
          dissented: [],
          queried: ['rpc.example'],
        },
      });

    const blocked = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest,
      trustState,
    });
    expect(blocked.status).toBe(451);
    const interstitial = gateUrl(blocked);
    expect(interstitial.pathname).toMatch(/\/pages\/onchain-unverified\.html$/);
    expect(interstitial.searchParams.get('target')).toBe(appUrl());
    expect(interstitial.searchParams.get('source')).toBe('rpc.example');
    expect(interstitial.searchParams.get('hash')).toBe(ethers.keccak256(ethers.toUtf8Bytes(html)));
    const token = interstitial.searchParams.get('token');
    expect(token).toBe('a'.repeat(43));

    const approvedRequest = request(appUrl());
    approvedRequest.headers.set(APPROVAL_HEADER, token);
    const approved = await handleOnchainAppRequest(approvedRequest, {
      chainRequest,
      trustState,
    });
    expect(approved.status).toBe(200);
    await expect(approved.text()).resolves.toBe(html);
    expect(chainRequest).toHaveBeenCalledTimes(1);

    const unchanged = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest,
      trustState,
    });
    expect(unchanged.status).toBe(200);
    await expect(unchanged.text()).resolves.toBe(html);

    const changed = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest,
      trustState,
    });
    expect(changed.status).toBe(451);
    expect(gateUrl(changed).searchParams.get('hash')).toBe(
      ethers.keccak256(ethers.toUtf8Bytes(changedHtml))
    );
  });

  test('blocks conflicting RPC answers without issuing a continue token', async () => {
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => ({
        result: encodedHtml('<h1>first answer</h1>'),
        trust: {
          level: 'unverified',
          method: 'direct',
          agreed: ['a.example'],
          dissented: ['b.example'],
          queried: ['a.example', 'b.example'],
        },
      })),
      trustState: createOnchainAppTrustState(),
    });

    expect(response.status).toBe(451);
    const interstitial = gateUrl(response);
    expect(interstitial.searchParams.get('conflict')).toBe('1');
    expect(interstitial.searchParams.get('dissented')).toBe('b.example');
    expect(interstitial.searchParams.has('token')).toBe(false);
  });

  test('rejects expired approval tokens', async () => {
    let time = 10;
    let sequence = 0;
    const trustState = createOnchainAppTrustState({
      now: () => time,
      createToken: () => `${String(sequence++).padStart(43, 'a')}`,
    });
    const chainRequest = jest.fn(async () => ({
      result: encodedHtml('<h1>app</h1>'),
      trust: { level: 'unverified', method: 'direct', agreed: ['rpc.example'] },
    }));

    const blocked = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest,
      trustState,
    });
    const token = gateUrl(blocked).searchParams.get('token');
    time += 5 * 60 * 1000 + 1;
    const expiredRequest = request(appUrl());
    expiredRequest.headers.set(APPROVAL_HEADER, token);

    const expired = await handleOnchainAppRequest(expiredRequest, {
      chainRequest,
      trustState,
    });
    expect(expired.status).toBe(451);
    expect(chainRequest).toHaveBeenCalledTimes(2);
  });

  test('binds approval tokens to the exact requested document URL', async () => {
    let sequence = 0;
    const trustState = createOnchainAppTrustState({
      createToken: () => String(sequence++).padStart(43, 'a'),
    });
    const chainRequest = jest.fn(async () => ({
      result: encodedHtml('<h1>app</h1>'),
      trust: { level: 'unverified', method: 'direct', agreed: ['rpc.example'] },
    }));
    const blocked = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest,
      trustState,
    });
    const wrongTarget = request(appUrl(1, '/other'));
    wrongTarget.headers.set(APPROVAL_HEADER, gateUrl(blocked).searchParams.get('token'));

    const stillBlocked = await handleOnchainAppRequest(wrongTarget, {
      chainRequest,
      trustState,
    });

    expect(stillBlocked.status).toBe(451);
    // The new method URL also probes resolveMode before its content call.
    expect(chainRequest).toHaveBeenCalledTimes(3);
  });

  test('rejects non-read methods without touching chain data', async () => {
    const chainRequest = jest.fn();
    const response = await handleOnchainAppRequest(request(appUrl(), 'POST'), { chainRequest });
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD');
    expect(chainRequest).not.toHaveBeenCalled();
  });

  test('returns 400 for a malformed contract URL', async () => {
    const chainRequest = jest.fn();
    const response = await handleOnchainAppRequest(request('web3://invalid:1/'), {
      chainRequest,
    });
    expect(response.status).toBe(400);
    expect(chainRequest).not.toHaveBeenCalled();
  });

  test('returns 502 when neither html() nor ERC-6860 returns valid content', async () => {
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => ({ result: '0x', source: 'direct', verified: false })),
    });
    expect(response.status).toBe(502);
    await expect(response.text()).resolves.toContain('did not return valid web3 content');
  });

  test('rejects an oversized ABI response before decoding it', async () => {
    const result = `0x${'00'.repeat(MAX_HTML_BYTES + 96)}`;
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => ({ result, source: 'direct', verified: false })),
    });
    expect(response.status).toBe(413);
  });

  test('bounds a stalled chain read', async () => {
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(() => new Promise(() => {})),
      timeoutMs: 5,
    });
    expect(response.status).toBe(504);
  });
});

describe('captureOnchainProvenance trust gate', () => {
  test('opens only the validated bundled interstitial for a blocked main frame', async () => {
    const html = '<h1>unverified app</h1>';
    const blocked = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => ({
        result: encodedHtml(html),
        trust: { level: 'unverified', method: 'direct', agreed: ['rpc.example'] },
      })),
      trustState: createOnchainAppTrustState({ createToken: () => 'a'.repeat(43) }),
    });
    const contents = {
      isDestroyed: jest.fn(() => false),
      loadURL: jest.fn(() => Promise.resolve()),
    };

    captureOnchainProvenance({
      resourceType: 'mainFrame',
      statusCode: blocked.status,
      url: appUrl(),
      responseHeaders: { [GATE_HEADER]: [blocked.headers.get(GATE_HEADER)] },
      webContents: contents,
    });
    await new Promise((resolve) => setImmediate(resolve));

    expect(contents.loadURL).toHaveBeenCalledWith(gateUrl(blocked).toString());
  });

  test('ignores a gate header bound to another app URL', async () => {
    const blocked = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => ({
        result: encodedHtml('<h1>unverified app</h1>'),
        trust: { level: 'unverified', method: 'direct', agreed: ['rpc.example'] },
      })),
      trustState: createOnchainAppTrustState({ createToken: () => 'a'.repeat(43) }),
    });
    const contents = { loadURL: jest.fn() };

    captureOnchainProvenance({
      resourceType: 'mainFrame',
      statusCode: blocked.status,
      url: appUrl(1, '/another-path'),
      responseHeaders: { [GATE_HEADER]: [blocked.headers.get(GATE_HEADER)] },
      webContents: contents,
    });

    expect(contents.loadURL).not.toHaveBeenCalled();
  });

  test('strips the approval token from a response that is not a navigation', async () => {
    const blocked = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => ({
        result: encodedHtml('<h1>unverified app</h1>'),
        trust: { level: 'unverified', method: 'direct', agreed: ['rpc.example'] },
      })),
      trustState: createOnchainAppTrustState({ createToken: () => 'a'.repeat(43) }),
    });
    const contents = { loadURL: jest.fn() };

    const result = captureOnchainProvenance({
      resourceType: 'xhr',
      statusCode: blocked.status,
      url: appUrl(),
      responseHeaders: {
        'Cache-Control': ['no-store'],
        [GATE_HEADER]: [blocked.headers.get(GATE_HEADER)],
      },
      webContents: contents,
    });

    expect(result).toEqual({ responseHeaders: { 'Cache-Control': ['no-store'] } });
    expect(JSON.stringify(result)).not.toContain('a'.repeat(43));
    expect(contents.loadURL).not.toHaveBeenCalled();
  });

  test('leaves unrelated subresource responses untouched', () => {
    expect(
      captureOnchainProvenance({
        resourceType: 'image',
        statusCode: 200,
        url: 'https://example.com/logo.png',
        responseHeaders: { 'Content-Type': ['image/png'] },
      })
    ).toBeNull();
  });
});

describe('guardOnchainAppRequest', () => {
  beforeEach(() => jest.clearAllMocks());

  test('allows a top-level navigation to an onchain app', () => {
    expect(
      guardOnchainAppRequest({ url: appUrl(), resourceType: 'mainFrame' })
    ).toBeNull();
    expect(log.warn).not.toHaveBeenCalled();
  });

  // The gate is only meaningful if web content cannot reach it: a page that
  // can fetch the 451 response reads the single-use approval token out of it
  // (no CORS is enforced on custom-scheme responses), replays it, and
  // pre-approves unverified app code for the session with no interstitial.
  test.each(['subFrame', 'xhr', 'image', 'script', 'other', undefined])(
    'cancels a %s request for an onchain app',
    (resourceType) => {
      expect(guardOnchainAppRequest({ url: appUrl(), resourceType })).toEqual({ cancel: true });
    }
  );

  test('cancels a mixed-case web3 URL that is not a navigation', () => {
    expect(
      guardOnchainAppRequest({ url: `WEB3://${ADDRESS}.eip155-1/`, resourceType: 'xhr' })
    ).toEqual({ cancel: true });
  });

  test('ignores requests for every other scheme', () => {
    expect(guardOnchainAppRequest({ url: 'https://example.com/', resourceType: 'xhr' })).toBeNull();
    expect(guardOnchainAppRequest({ url: 'ipfs://cid/x', resourceType: 'subFrame' })).toBeNull();
    expect(guardOnchainAppRequest({})).toBeNull();
  });
});

describe('registerOnchainAppProtocol private sessions', () => {
  beforeEach(() => jest.clearAllMocks());

  test('registers web3 and redacts a private contract URL from logs', async () => {
    const handlers = new Map();
    const targetSession = {
      protocol: { handle: (scheme, handler) => handlers.set(scheme, handler) },
    };
    chainData.request.mockRejectedValue(new Error('unavailable'));

    registerOnchainAppProtocol(targetSession, { privatePartition: 'private-test' });
    await handlers.get('web3')(request(appUrl(1, '/private/path')));

    const logged = [log.info, log.warn, log.error]
      .flatMap((fn) => fn.mock.calls)
      .map((call) => call.join(' '))
      .join('\n');
    expect(logged).not.toContain(ADDRESS.toLowerCase());
    expect(logged).not.toContain('private/path');
    expect(logged).toContain('web3://<private>');
  });
});

describe('onchain-app-guard registration', () => {
  // docs/security-audit-electron.md E-6: the guard is the only thing between
  // a page's background fetch and the web3 approval token, so a throw inside
  // it must cancel the request rather than let the dispatcher skip it.
  test('registers the frame guard fail-closed', () => {
    jest.isolateModules(() => {
      jest.doMock('../webrequest-dispatcher', () => ({ registerWebRequestHandler: jest.fn() }));
      const dispatcher = require('../webrequest-dispatcher');
      const fresh = require('./onchain-app-protocol');
      fresh.installOnchainProvenanceCapture();
      expect(dispatcher.registerWebRequestHandler).toHaveBeenCalledWith(
        'onBeforeRequest',
        'onchain-app-guard',
        fresh.guardOnchainAppRequest,
        { failClosed: true }
      );
    });
  });
});

describe('html() decoding off the main thread (#503 item 9)', () => {
  const fs = require('node:fs');
  const os = require('node:os');
  const path = require('node:path');
  let dir;

  beforeEach(() => {
    jest.clearAllMocks();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'onchain-html-worker-'));
    htmlWorker.resetForTest();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    htmlWorker.resetForTest();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function trustedResult(html) {
    return {
      result: encodedHtml(html),
      trust: { level: 'verified', method: 'myotis', agreed: ['myotis-p2p'] },
    };
  }

  test('decodes and hashes the document in the worker, not on the main thread', async () => {
    const html = '<!doctype html><h1>caf\u00e9 \u{1f680}</h1>';
    const run = jest.spyOn(htmlWorker, 'run');
    const decodeOnMain = jest.spyOn(ethers.Interface.prototype, 'decodeFunctionResult');
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => trustedResult(html)),
    });

    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe(html);
    expect(run).toHaveBeenCalledWith(
      'decode',
      { result: encodedHtml(html) },
      { signal: expect.any(AbortSignal) }
    );
    // The worker has its own copy of ethers; this one was never asked.
    expect(decodeOnMain).not.toHaveBeenCalled();
    const provenance = decodeOnchainProvenance(response.headers.get(PROVENANCE_HEADER));
    expect(provenance.htmlHash).toBe(ethers.keccak256(ethers.toUtf8Bytes(html)));
    expect(log.warn).not.toHaveBeenCalled();
  });

  test('carries a worker-reported error code back to the response', async () => {
    const scripted = path.join(dir, 'too-large-worker.js');
    fs.writeFileSync(
      scripted,
      `require('node:worker_threads').parentPort.on('message', function (m) {
         this.postMessage({ id: m.id, ok: false, code: 'ONCHAIN_APP_TOO_LARGE', error: 'too big' });
       });`
    );
    htmlWorker.resetForTest({ path: scripted });
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => trustedResult('<h1>x</h1>')),
    });
    expect(response.status).toBe(413);
  });

  test('rejects a malformed result in the worker', async () => {
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => ({ result: '0xzz', source: 'direct', verified: false })),
    });
    expect(response.status).toBe(502);
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining('Malformed contract response'));
  });

  test('decodes on the main thread only when the worker cannot run', async () => {
    htmlWorker.resetForTest({ path: path.join(dir, 'missing-worker.js') });
    const html = '<h1>fallback</h1>';
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => trustedResult(html)),
    });
    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe(html);
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining('[OnchainHtml] worker'));
  });

  test('a decode that hangs fails the request instead of falling back to main', async () => {
    const hanging = path.join(dir, 'hanging-worker.js');
    fs.writeFileSync(hanging, "require('node:worker_threads').parentPort.on('message', () => {});");
    htmlWorker.resetForTest({ path: hanging, timeoutMs: 100 });
    const decodeOnMain = jest.spyOn(ethers.Interface.prototype, 'decodeFunctionResult');
    const run = jest.spyOn(htmlWorker, 'run');
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => trustedResult('<h1>never</h1>')),
    });
    expect(response.status).toBe(502);
    await expect(run.mock.results[0].value).rejects.toBeInstanceOf(TaskWorkerTimeout);
    expect(decodeOnMain).not.toHaveBeenCalled();
  });

  function hangingWorker() {
    const hanging = path.join(dir, 'hanging-worker.js');
    fs.writeFileSync(hanging, "require('node:worker_threads').parentPort.on('message', () => {});");
    return hanging;
  }

  test('the request deadline covers the decode, not just the chain read', async () => {
    // The worker's own limit is far away; the request's 150 ms must still hold.
    htmlWorker.resetForTest({ path: hangingWorker(), timeoutMs: 60_000 });
    const run = jest.spyOn(htmlWorker, 'run');
    const decodeOnMain = jest.spyOn(ethers.Interface.prototype, 'decodeFunctionResult');
    const started = Date.now();
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return trustedResult('<h1>never</h1>');
      }),
      timeoutMs: 150,
    });
    expect(response.status).toBe(504);
    expect(Date.now() - started).toBeLessThan(2_000);
    // The abandoned decode is withdrawn from the worker, not left running.
    await expect(run.mock.results[0].value).rejects.toMatchObject({ name: 'AbortError' });
    expect(decodeOnMain).not.toHaveBeenCalled();
  });

  test('a cancelled navigation frees the decode worker for the next load', async () => {
    htmlWorker.resetForTest({ path: hangingWorker(), timeoutMs: 60_000 });
    const run = jest.spyOn(htmlWorker, 'run');
    const controller = new AbortController();
    const pending = handleOnchainAppRequest(request(appUrl(), 'GET', controller.signal), {
      chainRequest: jest.fn(async () => trustedResult('<h1>never</h1>')),
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    controller.abort();
    const response = await pending;
    expect(response.status).toBe(504);
    await expect(run.mock.results[0].value).rejects.toMatchObject({ name: 'AbortError' });
  });
});


describe('web3 name and contract calls', () => {
  const abi = ethers.AbiCoder.defaultAbiCoder();
  const verified = { level: 'verified' };
  const unverified = { level: 'unverified', method: 'direct' };
  const resolved = (trust = verified) => ({ address: CANONICAL_ADDRESS, chainId: 8453, trust });
  const namedUrl = 'web3://app.wei.eip155-1/html#section';

  test('redirects a verified name to the resolved contract and chain before executing code', async () => {
    const resolveName = jest.fn().mockResolvedValue(resolved());
    const chainRequest = jest.fn();
    const response = await handleOnchainAppRequest(request(namedUrl), { resolveName, chainRequest });
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe(`web3://${ADDRESS.toLowerCase()}.eip155-8453/html#section`);
    expect(resolveName).toHaveBeenCalledWith('app.wei', 1);
    expect(chainRequest).not.toHaveBeenCalled();
  });

  test('gates an unverified name even when contract code is verified', async () => {
    const resolveName = jest.fn().mockResolvedValue(resolved(unverified));
    const chainRequest = jest.fn().mockImplementation(async (_chain, _method, [tx]) => ({
      result: tx.data === '0xdd473fae' ? ethers.ZeroHash : encodedHtml('<h1>named app</h1>'),
      trust: verified,
    }));
    const trustState = createOnchainAppTrustState();
    const first = await handleOnchainAppRequest(request(namedUrl), { resolveName, chainRequest, trustState });
    expect(first.status).toBe(451);
    const gate = gateUrl(first);
    expect(gate.searchParams.get('contract')).toBe(CANONICAL_ADDRESS);
    expect(gate.searchParams.get('chain')).toBe('8453');
    const approved = request(namedUrl);
    approved.headers.set(APPROVAL_HEADER, gate.searchParams.get('token'));
    const response = await handleOnchainAppRequest(approved, { resolveName, chainRequest, trustState });
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toContain('.eip155-8453/html');
    expect(resolveName).toHaveBeenCalledTimes(1);
  });

  test('never offers approval for conflicting name results', async () => {
    const response = await handleOnchainAppRequest(request('web3://app.eth.eip155-1/'), {
      resolveName: async () => resolved({ ...unverified, dissented: ['other.example'] }),
      chainRequest: async () => ({ result: encodedHtml('<h1>app</h1>'), trust: verified }),
      trustState: createOnchainAppTrustState(),
    });
    expect(response.status).toBe(451);
    expect(gateUrl(response).searchParams.get('conflict')).toBe('1');
    expect(gateUrl(response).searchParams.has('token')).toBe(false);
  });

  test('passes explicit sender and typed method arguments to the contract', async () => {
    const chainRequest = jest.fn().mockImplementation(async (_chain, _method, [tx]) => ({
      result: tx.data === '0xdd473fae' ? ethers.ZeroHash : abi.encode(['uint256'], [42]),
      trust: verified,
    }));
    const from = '0x2222222222222222222222222222222222222222';
    const response = await handleOnchainAppRequest(request(
      `web3://${from}@${ADDRESS.toLowerCase()}.eip155-1/balanceOf/${from}?returns=(uint256)`
    ), { chainRequest });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(['0x2a']);
    expect(response.headers.get('content-type')).toBe('application/json');
    expect(chainRequest.mock.calls[1][2][0]).toEqual({
      to: CANONICAL_ADDRESS, from,
      data: ethers.id('balanceOf(address)').slice(0, 10) + abi.encode(['address'], [from]).slice(2),
    });
  });

  test('falls back from absent html() to manual mode at the root', async () => {
    const chainRequest = jest.fn().mockImplementation(async (_chain, _method, [tx]) => {
      if (tx.data === HTML_SELECTOR) throw new Error('execution reverted');
      return {
        result: tx.data === '0xdd473fae' ? ethers.encodeBytes32String('manual') : abi.encode(['bytes'], [ethers.toUtf8Bytes('<h1>manual</h1>')]),
        trust: verified,
      };
    });
    const response = await handleOnchainAppRequest(request(appUrl()), { chainRequest });
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('<h1>manual</h1>');
    expect(chainRequest.mock.calls[2][2][0].data).toBe('0x2f');
  });

  describe('path routes of an html() document', () => {
    const page = '<h1>app</h1>';
    const document = (overrides = {}) => jest.fn().mockImplementation(async (_chain, _method, [tx]) => {
      if (tx.data === HTML_SELECTOR) return { result: abi.encode(['string'], [page]), trust: verified };
      if (tx.data === '0xdd473fae') {
        if (overrides.mode) return { result: ethers.encodeBytes32String(overrides.mode), trust: verified };
        throw new Error('execution reverted');
      }
      if (overrides.method) return { result: overrides.method, trust: verified };
      throw new Error('execution reverted');
    });

    test('serves the document when the path names no contract method', async () => {
      const response = await handleOnchainAppRequest(request(`${appUrl()}projects/demo`), {
        chainRequest: document(),
      });
      expect(response.status).toBe(200);
      expect(response.headers.get('content-type')).toBe('text/html; charset=utf-8');
      expect(await response.text()).toBe(page);
    });

    test('still prefers a real contract method', async () => {
      const response = await handleOnchainAppRequest(request(`${appUrl()}version`), {
        chainRequest: document({ method: abi.encode(['bytes'], [ethers.toUtf8Bytes('7')]) }),
      });
      expect(await response.text()).toBe('7');
    });

    test('leaves a manual-mode contract in charge of its own paths', async () => {
      const response = await handleOnchainAppRequest(request(`${appUrl()}missing.txt`), {
        chainRequest: document({ mode: 'manual' }),
      });
      expect(response.status).toBe(502);
    });

    test('reports the call failure when the contract has no document either', async () => {
      const chainRequest = jest.fn().mockRejectedValue(new Error('execution reverted'));
      const response = await handleOnchainAppRequest(request(`${appUrl()}projects`), { chainRequest });
      expect(response.status).toBe(502);
    });
  });

  test('manual mode returns binary content and derives MIME from the path', async () => {
    const chainRequest = jest.fn().mockImplementation(async (_chain, _method, [tx]) => ({
      result: tx.data === '0xdd473fae' ? ethers.encodeBytes32String('manual') : abi.encode(['bytes'], ['0x00ff80']),
      trust: verified,
    }));
    const response = await handleOnchainAppRequest(request(appUrl(1, '/Art.png?raw=a+b#ignored')), { chainRequest });
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('image/png');
    expect(Buffer.from(await response.arrayBuffer())).toEqual(Buffer.from([0, 255, 128]));
    expect(ethers.toUtf8String(chainRequest.mock.calls[1][2][0].data)).toBe('/Art.png?raw=a+b');
  });

  test('resolves name arguments via address records and retains their trust', async () => {
    const resolveName = jest.fn().mockResolvedValue({ address: CANONICAL_ADDRESS, chainId: 1, trust: unverified });
    const chainRequest = jest.fn().mockImplementation(async (_chain, _method, [tx]) => ({
      result: tx.data === '0xdd473fae' ? ethers.ZeroHash : encodedHtml('<h1>read</h1>'), trust: verified,
    }));
    const response = await handleOnchainAppRequest(request(appUrl(1, '/balanceOf/app.gwei')), { resolveName, chainRequest, trustState: createOnchainAppTrustState() });
    expect(response.status).toBe(451);
    expect(resolveName).toHaveBeenCalledWith('app.gwei', 1, { contentContract: false });
  });

  test('includes name discovery in the navigation deadline', async () => {
    const response = await handleOnchainAppRequest(request(namedUrl), {
      resolveName: () => new Promise(() => {}), timeoutMs: 5,
    });
    expect(response.status).toBe(504);
  });
});


describe('ERC-8244 address-record discovery', () => {
  const trust = { level: 'verified', method: 'myotis' };

  test('detects non-empty HTML through the router and document worker', async () => {
    const chainRequest = jest.fn().mockResolvedValue({
      result: encodedHtml('<title>anon.wei</title><script>throw new Error("never execute")</script>'),
      trust,
    });
    await expect(probeOnchainHtml(CANONICAL_ADDRESS, 1, { chainRequest })).resolves.toEqual({ supported: true, trust });
    expect(chainRequest).toHaveBeenCalledWith(1, 'eth_call', [
      { to: CANONICAL_ADDRESS, data: HTML_SELECTOR }, 'latest',
    ], expect.objectContaining({ includeTrust: true, signal: expect.any(AbortSignal) }));
  });

  test.each([encodedHtml(''), '0x', '0x1234', 'not ABI data'])(
    'does not treat an empty or invalid html() response as a website: %s', async (result) => {
      await expect(probeOnchainHtml(CANONICAL_ADDRESS, 1, {
        chainRequest: async () => ({ result, trust }),
      })).resolves.toEqual({ supported: false, trust });
    }
  );

  test('keeps unverified discovery provenance', async () => {
    const unverified = { level: 'unverified', method: 'direct' };
    await expect(probeOnchainHtml(CANONICAL_ADDRESS, 1, {
      chainRequest: async () => ({ result: encodedHtml('<h1>app</h1>'), trust: unverified }),
    })).resolves.toEqual({ supported: true, trust: unverified });
  });

  test('reports a contract revert as unsupported', async () => {
    await expect(probeOnchainHtml(CANONICAL_ADDRESS, 1, {
      chainRequest: async () => { throw Object.assign(new Error('execution reverted'), { code: 'CALL_EXCEPTION' }); },
    })).resolves.toMatchObject({ supported: false });
  });

  test('propagates transient transport failures', async () => {
    await expect(probeOnchainHtml(CANONICAL_ADDRESS, 1, {
      chainRequest: async () => { throw new Error('RPC unavailable'); },
    })).rejects.toThrow('RPC unavailable');
  });

  test('bounds and cancels a stalled discovery read', async () => {
    const chainRequest = jest.fn(() => new Promise(() => {}));
    await expect(probeOnchainHtml(CANONICAL_ADDRESS, 1, { chainRequest, timeoutMs: 5 })).rejects.toMatchObject({ name: 'AbortError' });
    expect(chainRequest.mock.calls[0][3].signal.aborted).toBe(true);
  });

  test('refuses oversized discovery responses', async () => {
    const result = '0x' + '00'.repeat(MAX_HTML_BYTES + 96);
    await expect(probeOnchainHtml(CANONICAL_ADDRESS, 1, {
      chainRequest: async () => ({ result, trust }),
    })).rejects.toMatchObject({ code: 'ONCHAIN_APP_TOO_LARGE' });
  });
});

describe('name display metadata on contract redirects', () => {
  test('binds the name to the guest and exact redirect target, and consumes it once', async () => {
    const { ipcMain, webContents } = require('electron');
    const contents = { id: 710, hostWebContents: { id: 711 }, once: jest.fn() };
    webContents.fromId.mockImplementation((id) => id === contents.id ? contents : null);
    registerOnchainProvenanceIpc();
    const read = ipcMain.handle.mock.calls.at(-1)[1];
    const response = await handleOnchainAppRequest(request(appUrl()), {
      chainRequest: jest.fn(async () => ({
        result: encodedHtml('<h1>named site</h1>'), trust: { level: 'verified', method: 'myotis' },
      })),
    });
    const redirect = () => captureOnchainProvenance({
      resourceType: 'mainFrame', statusCode: 302, url: 'web3://anon.wei/',
      responseHeaders: { Location: [appUrl()] }, webContents: contents,
    });
    const commit = (url = appUrl(), guest = contents) => captureOnchainProvenance({
      resourceType: 'mainFrame', statusCode: 200, url,
      responseHeaders: { [PROVENANCE_HEADER]: [response.headers.get(PROVENANCE_HEADER)] },
      webContents: guest,
    });
    const lookup = (url = appUrl(), senderId = 711) => read(
      { sender: { id: senderId } }, { webContentsId: contents.id, url }
    );

    redirect();
    commit();
    expect(lookup()).toMatchObject({ contract: CANONICAL_ADDRESS, nameUrl: 'web3://anon.wei/' });
    expect(lookup(appUrl(), 999)).toBeNull();
    commit();
    expect(lookup()).not.toHaveProperty('nameUrl');

    redirect();
    commit(appUrl(100));
    expect(lookup(appUrl(100))).not.toHaveProperty('nameUrl');

    redirect();
    captureOnchainProvenance({ resourceType: 'mainFrame', statusCode: 200,
      url: 'https://example.com/', webContents: contents });
    commit();
    expect(lookup()).not.toHaveProperty('nameUrl');

    redirect();
    const destroyed = contents.once.mock.calls.find(([event]) => event === 'destroyed')[1];
    destroyed();
    commit();
    expect(lookup()).not.toHaveProperty('nameUrl');
  });
});
