# Contract-hosted Applications (ERC-8244)

Freedom has native support for the draft [ERC-8244](https://ethereum-magicians.org/t/erc-8244-contract-hosted-application-html/28407) `html()` interface: an application whose whole document lives in contract storage on an Ethereum-compatible chain, with no HTTP gateway and no page-selected RPC endpoint in the path.

Enter the ERC-4804-style form `web3://<contract>:<chainId>/` in the address bar; omitting `:<chainId>` defaults to Ethereum mainnet.

## Origin model

Freedom keeps the standard form in browser chrome, history, bookmarks, copying, and permission prompts, while the webview navigates to a Chromium-safe, chain-scoped origin internally:

```text
web3://0x00000095643CFfA7D9fae407a84dfCB6406456c6
→ web3://0x00000095643cffa7d9fae407a84dfcb6406456c6.eip155-1/
```

The `.eip155-<chainId>` suffix is invisible browser plumbing, not an extra DNS or gateway dependency. A bare all-hex `0x…` standard-scheme host is rejected by Chromium as an oversized IPv4 literal, while using the chain as a URL port triggers unsafe-port rules and excludes large chain IDs. The internal hostname gives each contract-and-chain pair a distinct web-storage origin; page scripts and DevTools therefore see that real internal origin, while Freedom's user-facing surfaces reverse-map it to the standard URL.

## Name resolution

`web3://app.eth/`, `web3://app.box/`, `web3://app.wei/`, and `web3://app.gwei/`
resolve through the existing Ethereum name services. ENS subdomains and supported
DNS names work through the Universal Resolver. The `w3://` shorthand is accepted
in the address bar and links. An optional address before `@` sets the read-only
call's sender, for example `web3://0x2222222222222222222222222222222222222222@app.eth/html`.

Following [ERC-6821](https://eips.ethereum.org/EIPS/eip-6821), the browser first
reads the `contentcontract` text record, and uses `addr` only when that record is
empty. Invalid records, zero addresses and failed reads fail the navigation.
An [ERC-3770](https://eips.ethereum.org/EIPS/eip-3770) prefix such as
`eth:0x…` or `base:0x…` overrides the destination chain; prefixes are matched
exactly against the chain catalog. A URL chain selects the name-service chain,
not an ENS wallet multicoin record. ENS is supported on chains with a local ENS
deployment; the existing WNS/GNS resolver uses mainnet.

The name redirects to the resolved contract-and-chain URL before any application
code runs. This keeps storage and wallet grants scoped to that identity, including
when a contentcontract record switches chains. Browser chrome, history and
bookmarks retain the name (for example, `web3://anon.wei/`), using the existing
ENS display-mapping helpers with a per-tab contract/chain/sender mapping. The
trust popover still identifies the resolved contract. Reload resolves the named
URL again on its original name-service chain. Unverified name results require
approval of the fetched document before redirecting, and conflicting results are
blocked. Private sessions keep separate approvals.

Bare names and `ens://` addresses retain contenthash precedence. A resolver that
reverts with `UnsupportedResolverProfile` for a record holds no such record: ENSv2
names often use a resolver serving only a few profiles, so the lookup continues
rather than failing. When contenthash is empty, an explicit `contentcontract` record opens the contract website. If
both website records are empty, Freedom checks the name's regular address record
for a non-empty ERC-8244 `html()` document. This supports names such as `anon.wei`
without requiring an additional website record. Addresses that do not serve HTML
are not treated as websites. Discovery uses the existing verified chain-data
router, document size limit and decode worker; the loaded document still passes
through the normal onchain trust gate and sandbox.

## Resolution

`web3` is registered as a privileged standard scheme in `src/main/index.js`, alongside `bzz`, `ipfs`, and `ipns`; the handler itself lives in `src/main/onchain/onchain-app-protocol.js`.

At the root, the handler first calls selector `0x33c34ac3` (`html()`) through the same capability-aware chain-data router the wallet uses (`src/main/networks/chain-data-router.js`): Myotis when available, then Colibri, RPC quorum, and direct RPC fallback according to network policy. A non-empty UTF-8 string is served unchanged as `text/html`. Fragment routes remain available to the app, and so do path routes that do not name a contract method (see Contract calls). Each document load has a 30-second browser deadline, covering both the chain read and the decode, and an 8 MiB decoded-document limit. The ABI decode and the Keccak-256 document hash run in a worker thread (`src/main/onchain/onchain-html-worker.js`), not in the protocol handler on Electron's main thread, where an 8 MiB document used to block every window for about a second. Documents are handed to that worker one at a time, each with its own 15-second decode limit counted from when the worker starts on it, so a queue of large documents (a restored session full of them) waits rather than timing out; a navigation that is cancelled or runs out of its 30 seconds leaves the queue, or stops the worker if it is already being decoded. The handler decodes on the main thread only when the worker cannot start at all, or crashes while decoding a document — that one document then costs the main thread its second, and the next one gets a fresh worker.

## Contract calls

When root `html()` discovery fails or returns an empty document, and for explicit
method URLs, Freedom follows [ERC-4804](https://eips.ethereum.org/EIPS/eip-4804)
with the corrections in [ERC-6860](https://eips.ethereum.org/EIPS/eip-6860):

- `resolveMode()` selects manual or automatic mode. Missing methods default to
  automatic mode; unknown mode words are rejected.
- Manual mode passes the path and query unchanged as UTF-8 calldata, preserving
  percent escapes and excluding the fragment. The default MIME type is HTML;
  a filename extension can select another type.
- Automatic mode ABI-encodes the method and path arguments. Integers, booleans,
  addresses and bytes are inferred; `type!value` supports explicit ABI types,
  including `string!hello`. Name arguments use address records, independently
  of `contentcontract`.
- Without `returns`, ABI-encoded bytes are returned directly. `returns=()` emits
  the raw result as a JSON hex-string array. Typed returns support tuples and
  arrays and encode integers as Ethereum JSON-RPC hex quantities. The last
  `returns` or legacy `returnTypes` attribute wins.

For example, `web3://app.eth/html` calls `html()` explicitly, while
`web3://app.eth/balanceOf/address!alice.eth?returns=(uint256)` returns JSON.
A path that does not name a callable method of an automatic-mode contract falls
back to the contract's `html()` document, so client-side routes in an ERC-8244
app survive a reload. The existing sandbox and navigation-only request
guard apply to all web3 content; external subresource fetching remains blocked.

## Security model

Contract HTML runs in a context-isolated webview with a response-enforced sandbox and default-deny content policy. Inline scripts/styles and embedded `data:`/`blob:` media work, but ambient network connections, external frames, workers, objects, scripted top-level redirects, and popups are blocked. Genuine user link clicks are handed back to Freedom's navigation chrome.

The app receives the existing EIP-1193/EIP-6963 wallet provider; reads and approvals are pinned to the chain encoded in its origin, and `wallet_switchEthereumChain` cannot silently move it to another chain. A global wallet-chain change does not emit a contradictory `chainChanged` event into a pinned app. Every contract-and-chain pair gets its own wallet permission key.

Private windows can render the document but continue to omit wallet providers, matching every other protocol.

## Scope

Registry fallback and upgrade-policy discovery, described as optional extensions in the ERC, are not inferred by the browser; an upgrade-aware resolver contract can expose its own `html()` result.
