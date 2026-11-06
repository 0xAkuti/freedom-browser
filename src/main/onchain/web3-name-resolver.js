// ERC-6821 contentcontract discovery uses the name service on the URL's
// chain. Wallet ENSIP-19 multicoin lookups have different semantics.
const { domainToUnicode } = require('node:url');
const { ethers } = require('ethers');
const { ens_normalize } = require('@adraffy/ens-normalize');
const chainData = require('../networks/chain-data-router');
const { ccipReadFetch } = require('../ens/ccip-fetch');

const RECORD_ABI = new ethers.Interface([
  'function text(bytes32,string) view returns (string)',
  'function addr(bytes32) view returns (address)',
]);
const TRUST_RANK = { verified: 2, 'user-configured': 1, unverified: 0 };

function weakestTrust(...records) {
  const rank = (trust) =>
    trust.level === 'unverified' && trust.dissented?.length ? -1 : (TRUST_RANK[trust.level] ?? 0);
  return records.filter(Boolean).reduce((weakest, trust) => {
    return !weakest || rank(trust) < rank(weakest) ? trust : weakest;
  }, null);
}

// The normal mainnet resolver preserves the user's verified-resolution
// policy, wildcard ENS and bounded CCIP-Read. Other ENS chains use the same
// Universal Resolver through the chain-data router, including CCIP callbacks.
async function readRecord(name, key, chainId) {
  const { resolveWeb3Record, universalResolverCall } = require('../ens-resolver');
  if (chainId === 1) return resolveWeb3Record(name, key);
  if (/\.(wei|gwei)$/i.test(name)) throw new Error('WNS and GNS resolve on mainnet only');
  const network = ethers.Network.from(chainId);
  const ens = network.getPlugin('org.ethers.plugins.network.Ens');
  if (!ens || ens.targetNetwork !== chainId) throw new Error('This chain does not have ENS');
  let trust = null;
  class RoutedEnsProvider extends ethers.AbstractProvider {
    async _detectNetwork() {
      return network;
    }
    async ccipReadFetch(transaction, data, urls) {
      return ccipReadFetch(transaction, data, urls);
    }
    async _perform(request) {
      if (request.method !== 'call') throw new Error('Unsupported name resolution request');
      const { to, data } = request.transaction;
      const result = await chainData.request(chainId, 'eth_call', [{ to, data }, 'latest'], {
        includeTrust: true,
      });
      trust = weakestTrust(trust, result.trust || { level: 'unverified' });
      return result.result;
    }
  }
  const provider = new RoutedEnsProvider(network, { cacheTimeout: -1 });
  try {
    const method = key == null ? 'addr' : 'text';
    const args = [ethers.namehash(name), ...(key == null ? [] : [key])];
    const { resolvedData } = await universalResolverCall(
      provider,
      name,
      RECORD_ABI.encodeFunctionData(method, args)
    );
    return { value: RECORD_ABI.decodeFunctionResult(method, resolvedData)[0], trust };
  } finally {
    provider.destroy();
  }
}

async function chainIdForPrefix(prefix) {
  // Ethereum's primary short name needs no catalog download.
  if (prefix === 'eth') return 1;
  const { getChainIdByShortName } = require('../networks/chain-catalog-host');
  return getChainIdByShortName(prefix);
}

async function resolveWeb3Name(
  name,
  chainId = 1,
  { read = readRecord, resolvePrefix = chainIdForPrefix, contentContract = true } = {}
) {
  const normalized = ens_normalize(domainToUnicode(name));
  if (!normalized.includes('.')) throw new Error('Unsupported name service');
  if (!Number.isSafeInteger(chainId) || chainId <= 0) throw new Error('Invalid name service chain');
  let trust = null;
  let value;
  if (contentContract) {
    const record = await read(normalized, 'contentcontract', chainId);
    value = record.value;
    trust = record.trust || { level: 'unverified' };
  }
  // Only a successful, empty text record permits fallback. A malformed
  // record or a failed read must never silently select the wallet address.
  if (!contentContract || value === '') {
    const record = await read(normalized, null, chainId);
    value = record.value;
    trust = weakestTrust(trust, record.trust || { level: 'unverified' });
  }
  const target = await parseContentContract(value, chainId, resolvePrefix);
  return { name: normalized, ...target, trust: trust || { level: 'unverified' } };
}

async function parseContentContract(value, chainId = 1, resolvePrefix = chainIdForPrefix) {
  if (typeof value !== 'string') throw new Error('Invalid contentcontract record');
  const parts = value.split(':');
  if (parts.length > 2 || parts.some((part) => !part))
    throw new Error('Invalid contentcontract record');
  if (!/^0x[0-9a-f]{40}$/i.test(parts.at(-1)))
    throw new Error('Invalid contentcontract address');
  const address = ethers.getAddress(parts.at(-1));
  if (address === ethers.ZeroAddress) throw new Error('Address not found');
  if (parts.length === 2) {
    chainId = await resolvePrefix(parts[0]);
    if (!Number.isSafeInteger(chainId) || chainId <= 0)
      throw new Error('Unknown contentcontract chain');
  }
  return { address, chainId };
}

module.exports = { parseContentContract, resolveWeb3Name, weakestTrust };
