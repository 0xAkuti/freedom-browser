const { ethers } = require('ethers');
const {
  buildWeb3Call,
  decodeWeb3Result,
  resolveMode,
  RESOLVE_MODE_SELECTOR,
} = require('./web3-call');
const abi = ethers.AbiCoder.defaultAbiCoder();
const address = '0x2222222222222222222222222222222222222222';
const parsed = (path, query = '') => ({ path, query });

test('uses the specified resolveMode selector and mode encodings', () => {
  expect(RESOLVE_MODE_SELECTOR).toBe(ethers.id('resolveMode()').slice(0, 10));
  expect(resolveMode(ethers.encodeBytes32String('manual'))).toBe('manual');
  expect(resolveMode(ethers.encodeBytes32String('auto'))).toBe('auto');
  expect(resolveMode(ethers.ZeroHash)).toBe('auto');
  expect(resolveMode('0x')).toBe('auto');
  expect(() => resolveMode(ethers.encodeBytes32String('other'))).toThrow(
    'Unsupported resolve mode'
  );
});

test('manual calldata preserves percent encoding, plus signs, query and path case', async () => {
  const options = await buildWeb3Call(parsed('/A%2fb.svg', '?q=x+y'), 'manual');
  expect(ethers.toUtf8String(options.data)).toBe('/A%2fb.svg?q=x+y');
  expect(options.contentType).toBe('image/svg+xml');
  expect(ethers.toUtf8String((await buildWeb3Call(parsed(''), 'manual')).data)).toBe('/');
});

test.each([
  ['/render/123', 'render(uint256)', [123n]],
  ['/render/bool!false', 'render(bool)', [false]],
  ['/render/true', 'render(bool)', [true]],
  ['/render/int8!-12', 'render(int8)', [-12n]],
  ['/render/uint!12', 'render(uint256)', [12n]],
  ['/render/0x1234', 'render(bytes)', ['0x1234']],
  [`/render/${address}`, 'render(address)', [address]],
  [`/render/0x${'ab'.repeat(32)}`, 'render(bytes32)', [`0x${'ab'.repeat(32)}`]],
  ['/render/string!Hello%20world%2Ftest%21', 'render(string)', ['Hello world/test!']],
])('ABI-encodes %s', async (path, signature, values) => {
  const options = await buildWeb3Call(parsed(path), 'auto');
  const iface = new ethers.Interface([`function ${signature}`]);
  expect(options.data).toBe(iface.encodeFunctionData(signature, values));
});

test('resolves untyped and explicit address arguments through the address resolver', async () => {
  const resolve = jest.fn().mockResolvedValue(address);
  const options = await buildWeb3Call(
    parsed('/balanceOf/app.wei/address!app.eth'),
    'auto',
    resolve
  );
  expect(resolve.mock.calls).toEqual([['app.wei'], ['app.eth']]);
  expect(options.data).toBe(
    ethers.id('balanceOf(address,address)').slice(0, 10) +
      abi.encode(['address', 'address'], [address, address]).slice(2)
  );
});

test.each([
  '/bad-method/1',
  '/render/uint7!1',
  '/render/uint8!256',
  '/render/bool!1',
  '/render/bytes2!0xff',
  '/render/bytes!0x1',
  '/render/string!%zz',
])('rejects invalid calls %s', async (path) => {
  await expect(buildWeb3Call(parsed(path), 'auto')).rejects.toThrow();
});

test('uses the final returns or returnTypes attribute and preserves literal plus in strings', async () => {
  const options = await buildWeb3Call(
    parsed('/render/string!a+b.css', '?returns=(bool)&returnTypes=(uint)'),
    'auto'
  );
  expect(options.returns).toEqual(['uint256']);
  expect(options.contentType).toBe('text/css');
  expect(options.data).toBe(
    ethers.id('render(string)').slice(0, 10) + abi.encode(['string'], ['a+b.css']).slice(2)
  );
});

test.each(['?x=1', '?returns=uint256', '?returns=(uint7)', '?returns=(function)', '?returns'])(
  'rejects invalid auto queries %s',
  async (query) => {
    await expect(buildWeb3Call(parsed('/render', query), 'auto')).rejects.toThrow();
  }
);

test('decodes ABI bytes without losing binary data', () => {
  const options = { returns: '', contentType: 'image/png' };
  const result = decodeWeb3Result(abi.encode(['bytes'], ['0x00ff80']), options);
  expect(Buffer.from(result.html)).toEqual(Buffer.from([0, 255, 128]));
  expect(result.htmlHash).toBe(ethers.keccak256('0x00ff80'));
  expect(result.contentType).toBe('image/png');
});

test('JSON return values follow Ethereum quantity encoding recursively', async () => {
  const options = await buildWeb3Call(
    parsed('/get', '?returns=(uint256,int256,bool,string,address,(uint256,string)[])'),
    'auto'
  );
  const encoded = abi.encode(options.returns, [0, -2, true, '0xABCDEF', address, [[42, 'nested']]]);
  const result = decodeWeb3Result(encoded, options);
  expect(JSON.parse(result.html.toString())).toEqual([
    '0x0',
    '-0x2',
    true,
    '0xABCDEF',
    address,
    [['0x2a', 'nested']],
  ]);
  expect(result.contentType).toBe('application/json');
});

test('raw returns wrap the ABI response as a JSON hex string', () => {
  expect(JSON.parse(decodeWeb3Result('0xabcd', { returns: '()' }).html.toString())).toEqual([
    '0xabcd',
  ]);
});

test('explicit /html calls decode the ERC-8244 string as HTML bytes', async () => {
  const options = await buildWeb3Call(parsed('/html'), 'auto');
  expect(options.data).toBe('0x33c34ac3');
  const result = decodeWeb3Result(
    abi.encode(['string'], ['<!doctype html><h1>hello</h1>']),
    options
  );
  expect(result.html.toString()).toBe('<!doctype html><h1>hello</h1>');
  expect(result.contentType).toBe('text/html');
});
