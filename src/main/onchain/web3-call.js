// ERC-4804 calls with ERC-6860's corrected ABI and response semantics.
// Pure response decoding also runs in onchain-html-worker.js.
const { ethers } = require('ethers');
const { assertHtmlResultSize, MAX_HTML_BYTES } = require('./onchain-html');

const RESOLVE_MODE_SELECTOR = '0xdd473fae';
const ABI = ethers.AbiCoder.defaultAbiCoder();
const MIME_TYPES = {
  html: 'text/html',
  htm: 'text/html',
  css: 'text/css',
  js: 'text/javascript',
  json: 'application/json',
  txt: 'text/plain',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  ico: 'image/x-icon',
  avif: 'image/avif',
  woff: 'font/woff',
  woff2: 'font/woff2',
  wasm: 'application/wasm',
  pdf: 'application/pdf',
  xml: 'application/xml',
  mp4: 'video/mp4',
  mp3: 'audio/mpeg',
};

function mimeType(filename, fallback) {
  const extension = filename.match(/\.([a-z0-9]+)$/i)?.[1]?.toLowerCase();
  return extension ? MIME_TYPES[extension] || 'application/octet-stream' : fallback;
}

function resolveMode(result) {
  // A non-ABI response is a failed resolveMode call, hence auto mode.
  if (!/^0x[0-9a-f]{64}$/i.test(result || '')) return 'auto';
  result = result.toLowerCase();
  if (result === ethers.encodeBytes32String('manual')) return 'manual';
  if (result === ethers.encodeBytes32String('auto') || BigInt(result) === 0n) return 'auto';
  throw new Error('Unsupported resolve mode');
}

function baseType(type) {
  if (['bool', 'address', 'bytes', 'string'].includes(type)) return true;
  const integer = type.match(/^(?:u?int)([0-9]*)$/);
  if (integer)
    return !integer[1] || (+integer[1] >= 8 && +integer[1] <= 256 && +integer[1] % 8 === 0);
  const bytes = type.match(/^bytes([0-9]+)$/);
  return !!bytes && +bytes[1] >= 1 && +bytes[1] <= 32;
}

async function argument(raw, resolveAddress) {
  const decoded = decodeURIComponent(raw);
  const explicit = decoded.match(/^([^!]+)!(.*)$/s);
  let type = explicit?.[1];
  let value = explicit ? explicit[2] : decoded;
  if (!type) {
    if (/^[0-9]+$/.test(value)) type = 'uint256';
    else if (/^0x[0-9a-f]{64}$/i.test(value)) type = 'bytes32';
    else if (/^0x[0-9a-f]{40}$/i.test(value)) type = 'address';
    else if (/^0x(?:[0-9a-f]{2})*$/i.test(value)) type = 'bytes';
    else if (value === 'true' || value === 'false') type = 'bool';
    else type = 'address';
  }
  if (!baseType(type)) throw new Error('Unsupported argument type');
  if (type === 'uint') type = 'uint256';
  if (type === 'int') type = 'int256';
  if (type === 'address') {
    value = /^0x[0-9a-f]{40}$/i.test(value)
      ? ethers.getAddress(value)
      : await resolveAddress(value);
  } else if (type === 'bool') {
    if (value !== 'true' && value !== 'false') throw new Error('Invalid boolean argument');
    value = value === 'true';
  } else if (/^u?int/.test(type)) {
    if (!/^-?[0-9]+$/.test(value)) throw new Error('Invalid integer argument');
    value = BigInt(value);
  } else if (type !== 'string' && !/^0x(?:[0-9a-f]{2})*$/i.test(value)) {
    throw new Error('Invalid bytes argument');
  }
  return { type, value };
}

function returnTypes(query) {
  let returns = '';
  // Percent decoding follows URI rules; '+' is a literal plus, not a space.
  for (const entry of query.replace(/^\?/, '').split('&').filter(Boolean)) {
    const index = entry.indexOf('=');
    if (index < 0) throw new Error('Invalid auto mode query');
    const key = decodeURIComponent(entry.slice(0, index));
    if (key !== 'returns' && key !== 'returnTypes')
      throw new Error('Unsupported auto mode query attribute');
    returns = decodeURIComponent(entry.slice(index + 1));
  }
  if (!returns || returns === '()') return returns;
  if (!returns.startsWith('(') || !returns.endsWith(')')) throw new Error('Invalid return types');
  const tuple = ethers.ParamType.from(`tuple${returns}`);
  const validate = (type) => {
    if (type.baseType === 'array')
      return (type.arrayLength === -1 || type.arrayLength > 0) && validate(type.arrayChildren);
    if (type.baseType === 'tuple') return type.components.every(validate);
    return baseType(type.type);
  };
  if (!validate(tuple)) throw new Error('Unsupported return type');
  return tuple.components.map((type) => type.format('sighash'));
}

async function buildWeb3Call(parsed, mode, resolveAddress) {
  if (mode === 'manual') {
    return {
      data: ethers.hexlify(ethers.toUtf8Bytes((parsed.path || '/') + parsed.query)),
      contentType: mimeType(parsed.path, 'text/html'),
      returns: '',
    };
  }
  const returns = returnTypes(parsed.query);
  if (!parsed.path || parsed.path === '/') return { data: '0x', returns };
  const [method, ...segments] = parsed.path.slice(1).split('/');
  if (!/^[a-z_$][a-z0-9_$]*$/i.test(method)) throw new Error('Invalid contract method');
  const args = [];
  // Sequential reads preserve the configured name-resolution budget.
  for (const segment of segments) args.push(await argument(segment, resolveAddress));
  const signature = `${method}(${args.map((arg) => arg.type).join(',')})`;
  return {
    data:
      ethers.id(signature).slice(0, 10) +
      ABI.encode(
        args.map((arg) => arg.type),
        args.map((arg) => arg.value)
      ).slice(2),
    returns,
    contentType:
      method === 'html' && !args.length && !returns
        ? 'text/html'
        : args.at(-1)?.type === 'string'
          ? mimeType(args.at(-1).value)
          : undefined,
  };
}

function jsonValue(value) {
  if (typeof value === 'bigint')
    return value < 0n ? `-0x${(-value).toString(16)}` : `0x${value.toString(16)}`;
  if (Array.isArray(value)) return Array.from(value, jsonValue);
  if (typeof value === 'string' && /^0x[0-9a-f]+$/i.test(value)) return value.toLowerCase();
  return value;
}

function decodeWeb3Result(result, options) {
  assertHtmlResultSize(result);
  if (typeof result !== 'string' || !/^0x(?:[0-9a-f]{2})*$/i.test(result)) {
    throw new Error('Malformed contract response');
  }
  let body;
  let contentType = options.contentType;
  if (options.returns) {
    const values = options.returns === '()' ? [result] : ABI.decode(options.returns, result);
    // Normalize only ABI hex data, never strings that happen to look like hex.
    const normalize = (value, type) => {
      if (!type) return value;
      if (type.baseType === 'array')
        return Array.from(value, (item) => normalize(item, type.arrayChildren));
      if (type.baseType === 'tuple')
        return Array.from(value, (item, i) => normalize(item, type.components[i]));
      return type.type === 'string' ? value : jsonValue(value);
    };
    body = Buffer.from(
      JSON.stringify(
        Array.from(values, (value, i) =>
          normalize(
            value,
            options.returns === '()' ? null : ethers.ParamType.from(options.returns[i])
          )
        )
      )
    );
    contentType = 'application/json';
  } else {
    body = Buffer.from(ethers.getBytes(ABI.decode(['bytes'], result)[0]));
  }
  if (body.length > MAX_HTML_BYTES) {
    const error = new Error("Contract response exceeds Freedom's 8 MiB limit");
    error.code = 'ONCHAIN_APP_TOO_LARGE';
    throw error;
  }
  return { html: body, htmlHash: ethers.keccak256(body), contentType };
}

module.exports = { RESOLVE_MODE_SELECTOR, buildWeb3Call, decodeWeb3Result, resolveMode };
