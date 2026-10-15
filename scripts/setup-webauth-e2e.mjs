#!/usr/bin/env node

// Provision an isolated, local-only Metal Dollar-compatible stack for the UI.
// The XMD treasury WASM is fetched from its public Proton deployment and pinned
// by code hash. It is installed on a disposable local chain alongside the
// standard xmd.token and xtokens account names so WebAuth can resolve their
// public ABIs. No mainnet transaction is ever submitted.
import crypto from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const frontend = process.env.METAL_DOLLAR_FRONTEND_DIR
  ? path.resolve(process.env.METAL_DOLLAR_FRONTEND_DIR)
  : path.resolve(repo, '../metal-dollar-frontend')
const frontendRequire = createRequire(path.join(frontend, 'package.json'))
const { Api, JsonRpc, JsSignatureProvider } = frontendRequire('@proton/js')

const TREASURY = 'xmd.treasury'
const XMD_TOKEN = 'xmd.token'
const COLLATERAL_TOKEN = 'xtokens'
const ORACLE = 'oracles'
// In Antelope/PulseVM, use the system account for code permission
const SYSTEM_CODE_PERMISSION = `${process.env.PULSEVM_SYSTEM_ACCOUNT || 'pulse'}.code`
const USER = process.env.WEBAUTH_ACCOUNT || 'sitoula'
const RPC_URL = process.env.PULSEVM_RPC_URL || 'http://127.0.0.1:9650/ext/bc/pulse'
const LOCAL_BLOCKCHAIN_ID = new URL(RPC_URL).pathname.split('/').filter(Boolean).at(-1)
const ARTIFACT_RPC = process.env.PULSEVM_ARTIFACT_RPC || 'https://proton.eosusa.io'
const collateralSymbol = '4,XUSDC'
const collateralPrecision = 4
const collateralTarget = 1_000
// Seed a second local asset to exercise a multi-collateral treasury listing.
const reserveSymbol = '4,XBTC'
const reservePrecision = 4
const reserveAmount = '100.0000 XBTC'
const xmdMintAmount = '10.000000 XMD'
const collateralMintAmount = '10.0000 XUSDC'
// The treasury's cap calculation starts from the per-collateral minSupply.
// Zero makes the allowed mint amount zero on a fresh local chain.
const collateralMintCapacity = 1_000_000_000
// Chosen from the existing feeds at runtime; index zero is the no-oracle sentinel.
let oracleFeedIndex

const ARTIFACTS = {
  treasury: { source: 'xmd.treasury', hash: 'f3174beb2e9ad782b7b15cdc97f09245093ee98d42d1c3af5aafc2dbb4cc00ab' },
  xmdToken: { source: 'xmd.token', hash: '7ec765ade76af9580f2a1907c3b35aa51b09e0aab029e59de67c2c98b0fc3f78' },
  collateralToken: { source: 'xtokens', hash: 'ea0f6aa5e2b023f230c39cd72498457f40629bb2b161f387a17465b1657b26ed' },
  oracle: { source: 'oracles', hash: '22174c4e9bde31f1201594337b732400f657e9350955ee59b3f3ce202e7f08da' },
}

function envValue(contents, name) {
  for (const line of contents.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/)
    if (match?.[1] !== name) continue
    let value = match[2]
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    } else {
      value = value.replace(/\s+#.*$/, '')
    }
    return value
  }
  return undefined
}

async function secret(name) {
  if (process.env[name]) return process.env[name]
  for (const file of ['.env.localnet', '.env']) {
    try {
      const value = envValue(await fs.readFile(path.join(repo, file), 'utf8'), name)
      if (value) return value
    } catch {
      // Continue to the next local environment file.
    }
  }
  return undefined
}

async function producerKey() {
  return secret('PULSEVM_PRODUCER_KEY')
}

function curlJson(url, body) {
  const response = execFileSync('curl', [
    '--fail', '--silent', '--show-error', '--max-time', '40',
    '-H', 'content-type: application/json',
    '--data-binary', JSON.stringify(body), url,
  ], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 })
  return JSON.parse(response)
}

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex')
}

async function fetchArtifact({ source, hash: expectedHash }, patchTreasury = false) {
  const base = `${ARTIFACT_RPC}/v1/chain`
  const live = curlJson(`${base}/get_code`, { account_name: source })
  if (live.code_hash !== expectedHash) {
    throw new Error(`Refusing changed ${source} code hash: ${live.code_hash}`)
  }
  const raw = curlJson(`${base}/get_raw_code_and_abi`, { account_name: source })
  let wasm = Buffer.from(raw.wasm, 'base64')
  const abi = Buffer.from(raw.abi, 'base64')
  if (hash(wasm) !== expectedHash) throw new Error(`Downloaded ${source} WASM did not match its pinned code hash`)
  if (patchTreasury) wasm = patchTreasuryWasm(wasm)
  return { wasm, abi, codeHash: hash(wasm) }
}

function eosNameValue(name) {
  const alphabet = '.12345abcdefghijklmnopqrstuvwxyz'
  const symbol = (character) => {
    const index = alphabet.indexOf(character)
    if (index < 0) throw new Error(`Invalid Antelope name character: ${character}`)
    return BigInt(index)
  }
  let value = 0n
  for (let index = 0; index < 13; index += 1) {
    const bits = index < 12 ? 5n : 4n
    value = (value << bits) | (index < name.length ? symbol(name[index]) : 0n)
  }
  return BigInt.asIntN(64, value)
}

function encodeSleb(value) {
  let remaining = BigInt(value)
  const encoded = []
  while (true) {
    let byte = Number(remaining & 0x7fn)
    remaining >>= 7n
    const signSet = (byte & 0x40) !== 0
    const done = (remaining === 0n && !signSet) || (remaining === -1n && signSet)
    if (!done) byte |= 0x80
    encoded.push(byte)
    if (done) return Buffer.from(encoded)
  }
}

function encodeUleb(value) {
  let remaining = Number(value)
  const encoded = []
  do {
    let byte = remaining & 0x7f
    remaining >>>= 7
    if (remaining !== 0) byte |= 0x80
    encoded.push(byte)
  } while (remaining !== 0)
  return Buffer.from(encoded)
}

function readUleb(buffer, offset) {
  let value = 0
  let shift = 0
  let cursor = offset
  while (cursor < buffer.length) {
    const byte = buffer[cursor++]
    value |= (byte & 0x7f) << shift
    if ((byte & 0x80) === 0) return { value, next: cursor }
    shift += 7
    if (shift > 35) throw new Error('Invalid WASM section length')
  }
  throw new Error('Truncated WASM section length')
}

function readWasmString(buffer, offset) {
  const length = readUleb(buffer, offset)
  const end = length.next + length.value
  if (end > buffer.length) throw new Error('Truncated WASM import string')
  return end
}

function importedFunctionCount(payload) {
  let cursor = readUleb(payload, 0)
  const count = cursor.value
  let functions = 0
  let offset = cursor.next
  for (let i = 0; i < count; i += 1) {
    offset = readWasmString(payload, offset)
    offset = readWasmString(payload, offset)
    const kind = payload[offset++]
    if (kind === 0) {
      functions += 1
      offset = readUleb(payload, offset).next
    } else if (kind === 1) {
      offset += 1
      const flags = readUleb(payload, offset)
      offset = readUleb(payload, flags.next).next
      if (flags.value & 1) offset = readUleb(payload, offset).next
    } else if (kind === 2) {
      const flags = readUleb(payload, offset)
      offset = readUleb(payload, flags.next).next
      if (flags.value & 1) offset = readUleb(payload, offset).next
    } else if (kind === 3) {
      offset += 2
    } else if (kind === 4) {
      offset += 1
      offset = readUleb(payload, offset).next
    } else {
      throw new Error(`Unknown WASM import kind ${kind}`)
    }
  }
  if (offset !== payload.length) throw new Error('Unexpected bytes in WASM import section')
  return functions
}

function patchCodeSection(payload, targetFunction, oldName, newName, initFunction) {
  const count = readUleb(payload, 0)
  let offset = count.next
  const bodies = []
  for (let index = 0; index < count.value; index += 1) {
    const bodySize = readUleb(payload, offset)
    const end = bodySize.next + bodySize.value
    if (end > payload.length) throw new Error('Truncated WASM function body')
    bodies.push(Buffer.from(payload.subarray(bodySize.next, end)))
    offset = end
  }
  if (offset !== payload.length) throw new Error('Unexpected bytes in WASM code section')
  const bodyIndex = targetFunction
  if (bodyIndex < 0 || bodyIndex >= bodies.length) throw new Error('Treasury apply function index is outside the code section')

  const matches = []
  for (let bodyIndex = 0; bodyIndex < bodies.length; bodyIndex += 1) {
    for (let index = 0; index <= bodies[bodyIndex].length - oldName.length; index += 1) {
      if (bodies[bodyIndex].subarray(index, index + oldName.length).equals(oldName)) matches.push({ bodyIndex, index })
    }
  }
  if (matches.length !== 1) throw new Error(`Expected one hard-coded xmd.token reference in treasury code, found ${matches.length}`)
  newName.copy(bodies[matches[0].bodyIndex], matches[0].index)

  const body = bodies[bodyIndex]
  const localGroups = readUleb(body, 0)
  let instructionOffset = localGroups.next
  for (let index = 0; index < localGroups.value; index += 1) {
    instructionOffset = readUleb(body, instructionOffset).next
    instructionOffset += 1
  }
  if (instructionOffset >= body.length) throw new Error('Treasury apply function has no instructions')
  const initializerCall = Buffer.concat([Buffer.from([0x10]), encodeUleb(initFunction)])
  bodies[bodyIndex] = Buffer.concat([body.subarray(0, instructionOffset), initializerCall, body.subarray(instructionOffset)])

  return Buffer.concat([
    encodeUleb(bodies.length),
    ...bodies.flatMap((entry) => [encodeUleb(entry.length), entry]),
  ])
}

function patchTreasuryWasm(input) {
  let wasm = Buffer.from(input)
  if (wasm.subarray(0, 8).toString('hex') !== '0061736d01000000') {
    throw new Error('Treasury artifact is not a WASM module')
  }
  let offset = 8
  const sections = []
  while (offset < wasm.length) {
    const sectionId = wasm[offset++]
    const sectionSize = readUleb(wasm, offset)
    const start = sectionSize.next
    const end = start + sectionSize.value
    if (end > wasm.length) throw new Error('Truncated WASM section')
    sections.push({ id: sectionId, payload: Buffer.from(wasm.subarray(start, end)) })
    offset = end
  }
  const importSection = sections.find((section) => section.id === 2)
  const codeSection = sections.find((section) => section.id === 10)
  const startSection = sections.find((section) => section.id === 8)
  if (!codeSection || !startSection) throw new Error('Treasury WASM did not have the expected code/start sections')
  const imports = importedFunctionCount(importSection?.payload || Buffer.from([0]))

  const oldName = encodeSleb(eosNameValue('xmd.token'))
  const newName = encodeSleb(eosNameValue(XMD_TOKEN))
  if (oldName.length !== newName.length) throw new Error('Treasury token-name patch would change WASM layout')
  const applyFunction = 131
  const initializerFunction = 136
  if (applyFunction < imports || initializerFunction < imports) throw new Error('Unexpected treasury function import layout')
  codeSection.payload = patchCodeSection(
    codeSection.payload,
    applyFunction - imports,
    oldName,
    newName,
    initializerFunction,
  )

  const rebuilt = [wasm.subarray(0, 8)]
  for (const section of sections) {
    if (section.id === 8) continue
    rebuilt.push(Buffer.from([section.id]), encodeUleb(section.payload.length), section.payload)
  }
  wasm = Buffer.concat(rebuilt)
  return wasm
}

const rpc = new JsonRpc(RPC_URL)

function keyAuthority(key) {
  return { threshold: 1, keys: [{ key, weight: 1 }], accounts: [], waits: [] }
}

async function waitFor(description, check) {
  const deadline = Date.now() + 45_000
  while (Date.now() < deadline) {
    try {
      if (await check()) return
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
  throw new Error(`Timed out waiting for ${description}`)
}

async function exists(account) {
  try {
    await rpc.get_account(account)
    return true
  } catch (error) {
    if (error?.status === 500 || error?.json?.code === 500 || /account.*not found|unknown account/i.test(String(error?.message))) return false
    throw error
  }
}

async function transact(api, actions) {
  const info = await rpc.get_info()
  const prefix = Number.parseInt(info.head_block_id.slice(16, 24).match(/../g).reverse().join(''), 16)
  const expiration = new Date(Date.now() + 120_000).toISOString().slice(0, 19)
  const result = await api.transact({ actions }, {
    transactionHeader: {
      expiration,
      ref_block_num: info.head_block_num & 0xffff,
      ref_block_prefix: prefix,
      max_net_usage_words: 0,
      max_cpu_usage_ms: 0,
      delay_sec: 0,
    },
  })
  console.log(`Submitted local transaction ${result.transaction_id}`)
}

async function createAccount(api, name, publicKey) {
  if (await exists(name)) return
  await transact(api, [{
    account: 'pulse', name: 'newaccount',
    authorization: [{ actor: 'pulse', permission: 'active' }],
    data: { creator: 'pulse', name, owner: keyAuthority(publicKey), active: keyAuthority(publicKey) },
  }])
  await waitFor(`account ${name}`, () => exists(name))
}

async function installContract(api, account, artifact, expectedTables, expectedActions) {
  const current = await rpc.fetch('/v1/chain/get_code_hash', { account_name: account }).catch(() => undefined)
  if (current?.code_hash !== artifact.codeHash) {
    await transact(api, [{
      account: 'pulse', name: 'setcode',
      authorization: [{ actor: account, permission: 'active' }],
      data: { account, vmtype: 0, vmversion: 0, code: artifact.wasm.toString('hex') },
    }])
    await waitFor(`code on ${account}`, async () => {
      const result = await rpc.fetch('/v1/chain/get_code_hash', { account_name: account })
      return result.code_hash === artifact.codeHash
    })
  }
  let currentAbi
  try { currentAbi = await rpc.get_abi(account) } catch {}
  const abiReady = (value) => expectedTables.every((name) => value?.abi?.tables?.some((table) => table.name === name))
    && expectedActions.every((name) => value?.abi?.actions?.some((action) => action.name === name))
  if (!abiReady(currentAbi)) {
    await transact(api, [{
      account: 'pulse', name: 'setabi',
      authorization: [{ actor: account, permission: 'active' }],
      data: { account, abi: artifact.abi.toString('hex') },
    }])
    await waitFor(`ABI on ${account}`, async () => abiReady(await rpc.get_abi(account)))
  }
}

function parseUnits(asset, precision) {
  const decimal = asset.split(' ')[0]
  const [whole, fractional = ''] = decimal.split('.')
  return BigInt(whole) * (10n ** BigInt(precision)) + BigInt(fractional.padEnd(precision, '0').slice(0, precision) || '0')
}

function formatUnits(units, symbol, precision) {
  const scale = 10n ** BigInt(precision)
  return `${units / scale}.${(units % scale).toString().padStart(precision, '0')} ${symbol}`
}

async function balance(contract, account, symbol) {
  const rows = await rpc.get_currency_balance(contract, account, symbol)
  return rows[0] || `0.${'0'.repeat(symbol === 'XMD' ? 6 : 4)} ${symbol}`
}

async function ensureCollateral(api) {
  const stats = await rpc.get_currency_stats(COLLATERAL_TOKEN, 'XUSDC')
  if (!stats?.XUSDC) {
    await transact(api, [{
      account: COLLATERAL_TOKEN, name: 'create',
      authorization: [{ actor: COLLATERAL_TOKEN, permission: 'active' }],
      data: { issuer: COLLATERAL_TOKEN, maximum_supply: '1000000000.0000 XUSDC' },
    }])
    await waitFor('XUSDC definition', async () => Boolean((await rpc.get_currency_stats(COLLATERAL_TOKEN, 'XUSDC'))?.XUSDC))
  } else if (stats.XUSDC.issuer !== COLLATERAL_TOKEN) {
    throw new Error(`Unexpected XUSDC issuer ${stats.XUSDC.issuer} on ${COLLATERAL_TOKEN}`)
  }

  const targets = [
    { account: USER, amount: BigInt(collateralTarget) * 10n ** BigInt(collateralPrecision) },
    { account: TREASURY, amount: BigInt(collateralTarget) * 10n ** BigInt(collateralPrecision) },
  ]
  const gaps = []
  for (const target of targets) {
    const current = parseUnits(await balance(COLLATERAL_TOKEN, target.account, 'XUSDC'), collateralPrecision)
    if (current < target.amount) gaps.push({ ...target, amount: target.amount - current })
  }
  const totalToIssue = gaps.reduce((total, item) => total + item.amount, 0n)
  if (totalToIssue === 0n) return

  const issuerBalance = parseUnits(await balance(COLLATERAL_TOKEN, COLLATERAL_TOKEN, 'XUSDC'), collateralPrecision)
  if (issuerBalance < totalToIssue) {
    const amount = totalToIssue - issuerBalance
    await transact(api, [{
      account: COLLATERAL_TOKEN, name: 'issue',
      authorization: [{ actor: COLLATERAL_TOKEN, permission: 'active' }],
      data: { to: COLLATERAL_TOKEN, quantity: formatUnits(amount, 'XUSDC', collateralPrecision), memo: 'Local WebAuth E2E inventory' },
    }])
    await waitFor('issuer XUSDC inventory', async () => parseUnits(await balance(COLLATERAL_TOKEN, COLLATERAL_TOKEN, 'XUSDC'), collateralPrecision) >= issuerBalance + amount)
  }
  for (const item of gaps) {
    const quantity = formatUnits(item.amount, 'XUSDC', collateralPrecision)
    await transact(api, [{
      account: COLLATERAL_TOKEN, name: 'transfer',
      authorization: [{ actor: COLLATERAL_TOKEN, permission: 'active' }],
      data: { from: COLLATERAL_TOKEN, to: item.account, quantity, memo: item.account === TREASURY ? 'deposit' : 'Local WebAuth E2E fixture' },
    }])
    await waitFor(`${item.account} XUSDC balance`, async () => parseUnits(await balance(COLLATERAL_TOKEN, item.account, 'XUSDC'), collateralPrecision) >= item.amount)
  }
}

async function ensureReserveDefinition(api) {
  const stats = await rpc.get_currency_stats(COLLATERAL_TOKEN, 'XBTC')
  if (!stats?.XBTC) {
    await transact(api, [{
      account: COLLATERAL_TOKEN, name: 'create',
      authorization: [{ actor: COLLATERAL_TOKEN, permission: 'active' }],
      data: { issuer: COLLATERAL_TOKEN, maximum_supply: '1000000000.0000 XBTC' },
    }])
    await waitFor('XBTC reserve token definition', async () => Boolean((await rpc.get_currency_stats(COLLATERAL_TOKEN, 'XBTC'))?.XBTC))
  }
}

async function ensureReserveAsset(api) {
  const treasuryBalance = parseUnits(await balance(COLLATERAL_TOKEN, TREASURY, 'XBTC'), reservePrecision)
  const target = parseUnits(reserveAmount, reservePrecision)
  const issuerBalance = parseUnits(await balance(COLLATERAL_TOKEN, COLLATERAL_TOKEN, 'XBTC'), reservePrecision)
  if (treasuryBalance >= target) return
  const missing = target - treasuryBalance
  if (issuerBalance < missing) {
    await transact(api, [{
      account: COLLATERAL_TOKEN, name: 'issue',
      authorization: [{ actor: COLLATERAL_TOKEN, permission: 'active' }],
      data: { to: COLLATERAL_TOKEN, quantity: formatUnits(missing - issuerBalance, 'XBTC', reservePrecision), memo: 'Local E2E reserve inventory' },
    }])
    await waitFor('XBTC reserve issuer inventory', async () => parseUnits(await balance(COLLATERAL_TOKEN, COLLATERAL_TOKEN, 'XBTC'), reservePrecision) >= missing)
  }
  await transact(api, [{
    account: COLLATERAL_TOKEN, name: 'transfer',
    authorization: [{ actor: COLLATERAL_TOKEN, permission: 'active' }],
    data: { from: COLLATERAL_TOKEN, to: TREASURY, quantity: formatUnits(missing, 'XBTC', reservePrecision), memo: 'deposit' },
  }])
  await waitFor('XBTC diversification reserve', async () => parseUnits(await balance(COLLATERAL_TOKEN, TREASURY, 'XBTC'), reservePrecision) >= target)
}

async function clearUnaccountedBootstrapSupply(api) {
  const stats = await rpc.get_currency_stats(XMD_TOKEN, 'XMD')
  if (!stats?.XMD) return
  const supply = parseUnits(stats.XMD.supply, 6)
  if (supply === 0n) return

  // An earlier demo bootstrap issued XMD directly, leaving treasury accounting
  // at zero. That makes the production mint-cap calculation correctly return
  // zero. Clear only that unaccounted fixture supply; reruns after a real mint
  // preserve the accounted supply and balances.
  let trackedMinted = 0
  try {
    const { rows } = await rpc.get_table_rows({ json: true, code: TREASURY, scope: TREASURY, table: 'tokens', limit: 100 })
    trackedMinted = rows.reduce((total, row) => total + Number(row.amountMinted || 0), 0)
  } catch {}
  if (trackedMinted > 0) return

  let userBalance = parseUnits(await balance(XMD_TOKEN, USER, 'XMD'), 6)
  let treasuryBalance = parseUnits(await balance(XMD_TOKEN, TREASURY, 'XMD'), 6)
  const otherSupply = supply - userBalance - treasuryBalance
  if (otherSupply !== 0n) {
    throw new Error('Cannot clear unaccounted XMD bootstrap supply: balances exist outside the demo user and treasury')
  }

  const currentCode = await rpc.fetch('/v1/chain/get_code_hash', { account_name: TREASURY }).catch(() => undefined)
  if (currentCode?.code_hash && !/^0+$/.test(currentCode.code_hash)) {
    await transact(api, [{
      account: 'pulse', name: 'setcode',
      authorization: [{ actor: TREASURY, permission: 'active' }],
      data: { account: TREASURY, vmtype: 0, vmversion: 0, code: '' },
    }])
    await waitFor('temporary treasury code removal for fixture cleanup', async () => {
      const result = await rpc.fetch('/v1/chain/get_code_hash', { account_name: TREASURY })
      return !result.code_hash || /^0+$/.test(result.code_hash)
    })
  }

  userBalance = parseUnits(await balance(XMD_TOKEN, USER, 'XMD'), 6)
  if (userBalance > 0n) {
    await transact(api, [{
      account: XMD_TOKEN, name: 'transfer',
      authorization: [{ actor: USER, permission: 'active' }],
      data: { from: USER, to: TREASURY, quantity: formatUnits(userBalance, 'XMD', 6), memo: 'Clear local unaccounted bootstrap supply' },
    }])
    await waitFor('fixture XMD returned to issuer', async () => parseUnits(await balance(XMD_TOKEN, TREASURY, 'XMD'), 6) >= treasuryBalance + userBalance)
  }
  treasuryBalance = parseUnits(await balance(XMD_TOKEN, TREASURY, 'XMD'), 6)
  if (treasuryBalance > 0n) {
    await transact(api, [{
      account: XMD_TOKEN, name: 'retire',
      authorization: [{ actor: TREASURY, permission: 'active' }],
      data: { quantity: formatUnits(treasuryBalance, 'XMD', 6), memo: 'Clear local unaccounted bootstrap supply' },
    }])
    await waitFor('unaccounted XMD supply cleared', async () => parseUnits((await rpc.get_currency_stats(XMD_TOKEN, 'XMD')).XMD.supply, 6) === 0n)
  }
}

async function configureOracle(api) {
  const { rows } = await rpc.get_table_rows({ json: true, code: ORACLE, scope: ORACLE, table: 'feeds', limit: 10 })
  const existingFixtureFeed = rows.find((row) => Number(row.index) > 0 && row.name === 'Local XUSDC USD' && row.description === 'Fixed 1.0 local E2E price')
  oracleFeedIndex = existingFixtureFeed
    ? Number(existingFixtureFeed.index)
    : Math.max(0, ...rows.map((row) => Number(row.index))) + 1
  const feed = {
    account: 'pulse', index: oracleFeedIndex,
    name: 'Local XUSDC USD', description: 'Fixed 1.0 local E2E price',
    aggregate_function: 'last', data_type: 'double',
    config: [{ key: 'data_window_size', value: 1 }, { key: 'data_freshness_sec', value: 86400 }],
    providers: ['pulse'],
  }
  const auth = [{ actor: ORACLE, permission: 'active' }, { actor: 'pulse', permission: 'active' }]
  await transact(api, [{ account: ORACLE, name: 'setfeed', authorization: auth, data: feed }])
  await waitFor('local oracle feed', async () => {
    const result = await rpc.get_table_rows({ json: true, code: ORACLE, scope: ORACLE, table: 'feeds', limit: 10 })
    return result.rows.some((row) => Number(row.index) === oracleFeedIndex)
  })
  await transact(api, [{
    account: ORACLE, name: 'feed', authorization: [{ actor: 'pulse', permission: 'active' }],
    data: { account: 'pulse', feed_index: oracleFeedIndex, data: { d_string: null, d_uint64_t: null, d_double: 1.0 } },
  }])
  await waitFor('fixed local oracle price', async () => {
    const result = await rpc.get_table_rows({ json: true, code: ORACLE, scope: ORACLE, table: 'data', limit: 10 })
    return result.rows.some((row) => Number(row.feed_index) === oracleFeedIndex && Number(row.aggregate?.d_double) === 1)
  })
}

async function setupRoundTrip(api) {
  const before = {
    xmd: parseUnits(await balance(XMD_TOKEN, USER, 'XMD'), 6),
    collateral: parseUnits(await balance(COLLATERAL_TOKEN, USER, 'XUSDC'), collateralPrecision),
    treasuryCollateral: parseUnits(await balance(COLLATERAL_TOKEN, TREASURY, 'XUSDC'), collateralPrecision),
  }
  const mintUnits = parseUnits(collateralMintAmount, collateralPrecision)
  const expectedMint = parseUnits(xmdMintAmount, 6)
  await transact(api, [{
    account: COLLATERAL_TOKEN, name: 'transfer',
    authorization: [{ actor: USER, permission: 'active' }],
    data: { from: USER, to: TREASURY, quantity: collateralMintAmount, memo: 'mint' },
  }])
  await waitFor('minted XMD', async () => parseUnits(await balance(XMD_TOKEN, USER, 'XMD'), 6) === before.xmd + expectedMint)

  const redeemUnits = parseUnits('5.000000 XMD', 6)
  await transact(api, [{
    account: XMD_TOKEN, name: 'transfer',
    authorization: [{ actor: USER, permission: 'active' }],
    data: { from: USER, to: TREASURY, quantity: '5.000000 XMD', memo: 'redeem,XUSDC' },
  }])
  await waitFor('redeemed XUSDC', async () =>
    parseUnits(await balance(XMD_TOKEN, USER, 'XMD'), 6) === before.xmd + expectedMint - redeemUnits
    && parseUnits(await balance(COLLATERAL_TOKEN, USER, 'XUSDC'), collateralPrecision) === before.collateral - mintUnits + redeemUnits / 100n,
  )
  const after = {
    xmd: await balance(XMD_TOKEN, USER, 'XMD'),
    collateral: await balance(COLLATERAL_TOKEN, USER, 'XUSDC'),
    treasuryCollateral: await balance(COLLATERAL_TOKEN, TREASURY, 'XUSDC'),
  }
  console.log(`Local round trip passed: user XMD=${after.xmd}, XUSDC=${after.collateral}, treasury XUSDC=${after.treasuryCollateral}`)
}

async function main() {
  const endpoint = new URL(RPC_URL)
  if (!['127.0.0.1', 'localhost', '::1'].includes(endpoint.hostname)) throw new Error('Refusing a non-loopback PulseVM RPC')
  const [userKey, producer] = await Promise.all([secret('WEBAUTH_PKEY'), producerKey()])
  if (!userKey || !producer) throw new Error('Set WEBAUTH_PKEY and PULSEVM_PRODUCER_KEY in .env.localnet or the environment')

  const info = await rpc.get_info()
  if (process.env.PULSEVM_CHAIN_ID && info.chain_id !== process.env.PULSEVM_CHAIN_ID) {
    throw new Error(`Local chain ID mismatch: expected ${process.env.PULSEVM_CHAIN_ID}, got ${info.chain_id}`)
  }
  const signatures = new JsSignatureProvider([producer, userKey])
  const api = new Api({ rpc, signatureProvider: signatures, textDecoder: new TextDecoder(), textEncoder: new TextEncoder() })
  const publicKeys = await signatures.getAvailableKeys()
  const [producerPublicKey, userPublicKey] = publicKeys
  if (!producerPublicKey || !userPublicKey) throw new Error('Could not derive both local signer public keys')

  console.log(`Configuring local WebAuth demo on chain ${info.chain_id}`)
  const artifacts = await Promise.all([
    fetchArtifact(ARTIFACTS.treasury, true),
    fetchArtifact(ARTIFACTS.xmdToken),
    fetchArtifact(ARTIFACTS.collateralToken),
    fetchArtifact(ARTIFACTS.oracle),
  ])
  const [treasuryArtifact, xmdArtifact, collateralArtifact, oracleArtifact] = artifacts
  if (process.argv.includes('--prepare-only')) {
    console.log(`Prepared pinned treasury ${ARTIFACTS.treasury.hash} as local code ${treasuryArtifact.codeHash}`)
    return
  }

  for (const [name, key] of [[USER, userPublicKey], [TREASURY, producerPublicKey], [XMD_TOKEN, producerPublicKey], [COLLATERAL_TOKEN, producerPublicKey], [ORACLE, producerPublicKey]]) {
    await createAccount(api, name, key)
  }
  await installContract(api, XMD_TOKEN, xmdArtifact, ['accounts', 'stat'], ['create', 'issue', 'transfer'])
  await installContract(api, COLLATERAL_TOKEN, collateralArtifact, ['accounts', 'stat'], ['create', 'issue', 'transfer'])
  await installContract(api, ORACLE, oracleArtifact, ['feeds', 'data'], ['setfeed', 'feed'])
  const xmdStats = await rpc.get_currency_stats(XMD_TOKEN, 'XMD')
  if (!xmdStats?.XMD) {
    await transact(api, [{
      account: XMD_TOKEN, name: 'create', authorization: [{ actor: XMD_TOKEN, permission: 'active' }],
      data: { issuer: TREASURY, maximum_supply: '1000000000.000000 XMD' },
    }])
    await waitFor('XMD token definition', async () => Boolean((await rpc.get_currency_stats(XMD_TOKEN, 'XMD'))?.XMD))
  } else if (xmdStats.XMD.issuer !== TREASURY) {
    throw new Error(`Unexpected XMD issuer ${xmdStats.XMD.issuer} on ${XMD_TOKEN}`)
  }
  await clearUnaccountedBootstrapSupply(api)

  // Ensure XMD token is properly created with correct max_supply
  const xmdCurrentStats = await rpc.get_currency_stats(XMD_TOKEN, 'XMD')
  if (xmdCurrentStats?.XMD?.max_supply?.split(' ')[0] === '0') {
    console.log('Fixing XMD token max_supply (corrupted stat row detected)...')

    // Strategy: Issue 1 token to TREASURY with full max_supply
    // This forces the token contract to update the stat row with correct values
    const blockInfo = await rpc.get_info()
    const prefix = Number.parseInt(blockInfo.head_block_id.slice(16, 24).match(/../g).reverse().join(''), 16)

    try {
      // Use issue action to force stat row initialization with correct max_supply
      await api.transact(
        {
          actions: [{
            account: XMD_TOKEN,
            name: 'issue',
            authorization: [{ actor: TREASURY, permission: 'active' }],
            data: { to: TREASURY, quantity: '0.000001 XMD', memo: 'init' },
          }],
        },
        {
          transactionHeader: {
            expiration: new Date(Date.now() + 120_000).toISOString().slice(0, 19),
            ref_block_num: blockInfo.head_block_num & 0xffff,
            ref_block_prefix: prefix,
            max_net_usage_words: 0,
            max_cpu_usage_ms: 0,
            delay_sec: 0,
          },
        },
      )

      await waitFor('XMD token stat fixed', async () => {
        const stats = await rpc.get_currency_stats(XMD_TOKEN, 'XMD')
        const maxSupply = stats?.XMD?.max_supply?.split(' ')[0] || '0'
        return parseFloat(maxSupply) > 0
      }, 10000)

      console.log('  ✓ XMD token max_supply corrected')
    } catch (err) {
      console.error('  ⚠️  Could not fix XMD token via issue. Stat row may still be corrupted.')
      console.error('     Workaround: test collateral transfers (XUSDC) instead of XMD minting')
      // Don't fail setup—continue with partial functionality
    }
  }

  await ensureReserveDefinition(api)
  await installContract(api, TREASURY, treasuryArtifact, ['tokens', 'xmdglobals'], ['settoken', 'setglobals'])

  const treasuryAuthority = await rpc.get_account(TREASURY)
  const active = treasuryAuthority.permissions.find((permission) => permission.perm_name === 'active')
  if (!active?.required_auth?.accounts?.some((entry) => entry.permission?.actor === TREASURY && entry.permission?.permission === SYSTEM_CODE_PERMISSION)) {
    await transact(api, [{
      account: 'pulse', name: 'updateauth',
      authorization: [{ actor: TREASURY, permission: 'active' }],
      data: {
        account: TREASURY, permission: 'active', parent: 'owner',
        auth: {
          threshold: 1,
          keys: [{ key: producerPublicKey, weight: 1 }],
          accounts: [{ permission: { actor: TREASURY, permission: SYSTEM_CODE_PERMISSION }, weight: 1 }],
          waits: [],
        },
      },
    }])
    await waitFor('treasury inline-action permission', async () => {
      const result = await rpc.get_account(TREASURY)
      const permission = result.permissions.find((item) => item.perm_name === 'active')
      return permission?.required_auth?.accounts?.some((entry) => entry.permission?.actor === TREASURY && entry.permission?.permission === SYSTEM_CODE_PERMISSION)
    })
  }

  await configureOracle(api)
  await transact(api, [{
    account: TREASURY, name: 'setglobals', authorization: [{ actor: TREASURY, permission: 'active' }],
    data: { globals: { isPaused: false, feeAccount: 'pulse', minOraclePrice: 0.95 } },
  }])
  await transact(api, [{
    account: TREASURY, name: 'settoken', authorization: [{ actor: TREASURY, permission: 'active' }],
    data: {
      symbol: { sym: collateralSymbol, contract: COLLATERAL_TOKEN },
      isMintEnabled: true, isRedeemEnabled: true,
      maxTreasuryPercent: 99.99, minSupply: collateralMintCapacity, mintFee: 0, redemptionFee: 0,
      oracleIndex: oracleFeedIndex, isLiquidationEnabled: false,
    },
  }])
  await transact(api, [{
    account: TREASURY, name: 'settoken', authorization: [{ actor: TREASURY, permission: 'active' }],
    data: {
      symbol: { sym: reserveSymbol, contract: COLLATERAL_TOKEN },
      isMintEnabled: false, isRedeemEnabled: false,
      maxTreasuryPercent: 99.99, minSupply: 0, mintFee: 0, redemptionFee: 0,
      oracleIndex: oracleFeedIndex, isLiquidationEnabled: false,
    },
  }])
  await waitFor('supported XUSDC collateral row', async () => {
    const result = await rpc.get_table_rows({ json: true, code: TREASURY, scope: TREASURY, table: 'tokens', limit: 20 })
    return result.rows.some((row) => row.symbol?.contract === COLLATERAL_TOKEN && row.symbol?.sym === collateralSymbol)
  })
  await ensureCollateral(api)
  await ensureReserveAsset(api)

  console.log(`Configured ${TREASURY} with ${COLLATERAL_TOKEN} XUSDC at a local 1.0 oracle price.`)
  console.log(`\n📋 Frontend Environment Variables:`)
  console.log(`   VITE_CHAIN=pulsevm-test`)
  console.log(`   VITE_PULSEVM_TEST_RPC_URL=${RPC_URL}`)
  console.log(`   VITE_PULSEVM_TEST_CHAIN_ID=${info.chain_id}`)
  console.log(`   VITE_PULSEVM_TREASURY_ADDRESS=${TREASURY}`)
  console.log(`   VITE_PULSEVM_TOKEN_ADDRESS=${XMD_TOKEN}`)
  console.log(`\n💰 Collateral inventory:`)
  console.log(`   ${USER}: ${await balance(COLLATERAL_TOKEN, USER, 'XUSDC')}`)
  console.log(`   ${TREASURY}: ${await balance(COLLATERAL_TOKEN, TREASURY, 'XUSDC')}`)
  console.log(`\n📦 Reserve diversification:`)
  console.log(`   ${TREASURY}: ${await balance(COLLATERAL_TOKEN, TREASURY, 'XBTC')} (disabled, concentration limit)`)
  if (process.argv.includes('--roundtrip')) {
    console.log(`\n🔄 Running mint/redeem round trip...`)
    await setupRoundTrip(api)
  }
}

main().catch((error) => {
  console.error(error?.message || String(error))
  process.exitCode = 1
})
