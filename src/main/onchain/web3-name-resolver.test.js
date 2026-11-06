jest.mock('../networks/chain-data-router', () => ({ request: jest.fn() }));
jest.mock('../ens/ccip-fetch', () => ({ ccipReadFetch: jest.fn() }));
jest.mock('../ens-resolver', () => ({
  resolveWeb3Record: jest.fn(),
  universalResolverCall: jest.fn(async (provider, _name, data) => ({
    resolvedData: await provider.call({ to: '0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe', data }),
  })),
}));

const { ethers } = require('ethers');
const { resolveWeb3Name, weakestTrust } = require('./web3-name-resolver');

const ADDRESS = '0x2222222222222222222222222222222222222222';
const verified = { level: 'verified' };
const unverified = { level: 'unverified', method: 'direct' };

test.each(['app.eth', 'app.box', 'app.wei', 'app.gwei', 'sub.app.eth'])(
  'prefers contentcontract for %s',
  async (name) => {
    const read = jest.fn().mockResolvedValue({ value: ADDRESS, trust: verified });
    await expect(resolveWeb3Name(name, 1, { read })).resolves.toEqual({
      name,
      address: ADDRESS,
      chainId: 1,
      trust: verified,
    });
    expect(read).toHaveBeenCalledTimes(1);
    expect(read).toHaveBeenCalledWith(name, 'contentcontract', 1);
  }
);

test('falls back to addr only for a successfully read empty text record', async () => {
  const read = jest
    .fn()
    .mockResolvedValueOnce({ value: '', trust: unverified })
    .mockResolvedValueOnce({ value: ADDRESS, trust: verified });
  await expect(resolveWeb3Name('APP.ETH', 1, { read })).resolves.toMatchObject({
    address: ADDRESS,
    trust: unverified,
  });
  expect(read).toHaveBeenNthCalledWith(2, 'app.eth', null, 1);
});

test.each(['garbage', '0x1234', ethers.ZeroAddress, `bad:prefix:${ADDRESS}`, `:${ADDRESS}`])(
  'does not fall back on an invalid contentcontract %s',
  async (value) => {
    const read = jest.fn().mockResolvedValue({ value, trust: verified });
    await expect(resolveWeb3Name('app.eth', 1, { read })).rejects.toThrow();
    expect(read).toHaveBeenCalledTimes(1);
  }
);

test('does not mistake a failed text lookup for an absent record', async () => {
  const read = jest.fn().mockRejectedValue(new Error('network failure'));
  await expect(resolveWeb3Name('app.eth', 1, { read })).rejects.toThrow('network failure');
  expect(read).toHaveBeenCalledTimes(1);
});

test('looks up names on the URL chain before applying the ERC-3770 destination', async () => {
  const read = jest.fn().mockResolvedValue({ value: `base:${ADDRESS}`, trust: verified });
  const resolvePrefix = jest.fn().mockResolvedValue(8453);
  await expect(
    resolveWeb3Name('app.eth', 11155111, { read, resolvePrefix })
  ).resolves.toMatchObject({
    address: ADDRESS,
    chainId: 8453,
  });
  expect(read).toHaveBeenCalledWith('app.eth', 'contentcontract', 11155111);
  expect(resolvePrefix).toHaveBeenCalledWith('base');
});

test('rejects an unknown chain prefix', async () => {
  await expect(
    resolveWeb3Name('app.wei', 1, {
      read: async () => ({ value: `unknown:${ADDRESS}`, trust: verified }),
      resolvePrefix: async () => null,
    })
  ).rejects.toThrow('Unknown contentcontract chain');
});

test('address arguments use addr rather than contentcontract', async () => {
  const read = jest.fn().mockResolvedValue({ value: ADDRESS, trust: verified });
  await resolveWeb3Name('app.wei', 1, { read, contentContract: false });
  expect(read).toHaveBeenCalledTimes(1);
  expect(read).toHaveBeenCalledWith('app.wei', null, 1);
});

test('retains conflicts and the weakest resolution trust', () => {
  const conflict = { ...unverified, dissented: ['rpc.example'] };
  expect(weakestTrust(verified, unverified)).toBe(unverified);
  expect(weakestTrust(conflict, unverified)).toBe(conflict);
  expect(weakestTrust(unverified, conflict)).toBe(conflict);
});


test('uses the configured mainnet name-resolution service by default', async () => {
  const resolver = require('../ens-resolver');
  resolver.resolveWeb3Record.mockResolvedValue({ value: ADDRESS, trust: verified });
  await expect(resolveWeb3Name('app.eth')).resolves.toMatchObject({ address: ADDRESS, trust: verified });
  expect(resolver.resolveWeb3Record).toHaveBeenCalledWith('app.eth', 'contentcontract');
});

test('routes a Sepolia ENS lookup to Sepolia and keeps its trust metadata', async () => {
  const router = require('../networks/chain-data-router');
  router.request.mockClear();
  router.request.mockResolvedValue({
    result: ethers.AbiCoder.defaultAbiCoder().encode(['string'], [ADDRESS]), trust: verified,
  });
  await expect(resolveWeb3Name('app.eth', 11155111)).resolves.toMatchObject({
    address: ADDRESS, chainId: 11155111, trust: verified,
  });
  expect(router.request).toHaveBeenCalledWith(11155111, 'eth_call', [expect.objectContaining({
    data: expect.stringMatching(/^0x59d1d43c/),
  }), 'latest'], { includeTrust: true });
});

test('does not reuse mainnet ENS on a chain without its own deployment', async () => {
  const router = require('../networks/chain-data-router');
  router.request.mockClear();
  await expect(resolveWeb3Name('app.eth', 8453)).rejects.toThrow('does not have ENS');
  expect(router.request).not.toHaveBeenCalled();
});

test('treats missing record provenance as unverified', async () => {
  const read = jest.fn()
    .mockResolvedValueOnce({ value: '' })
    .mockResolvedValueOnce({ value: ADDRESS, trust: verified });
  await expect(resolveWeb3Name('app.eth', 1, { read })).resolves.toMatchObject({ trust: { level: 'unverified' } });
});
