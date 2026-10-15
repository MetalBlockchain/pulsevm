#!/usr/bin/env node

// E2E test using collateral transfers only (avoids XMD token issue)
// Tests: wallet auth, RPC connectivity, transaction signing, state verification
import fs from 'node:fs/promises'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const frontend = process.env.METAL_DOLLAR_FRONTEND_DIR
  ? path.resolve(process.env.METAL_DOLLAR_FRONTEND_DIR)
  : path.resolve(repo, '../metal-dollar-frontend')
const frontendRequire = createRequire(path.join(frontend, 'package.json'))
const { Api, JsonRpc, JsSignatureProvider } = frontendRequire('@proton/js')

const TREASURY = 'xmd.treasury'
const COLLATERAL_TOKEN = 'xtokens'
const USER = process.env.WEBAUTH_ACCOUNT || 'sitoula'
const RPC_URL = process.env.PULSEVM_RPC_URL || 'http://127.0.0.1:9650/ext/bc/pulse'

async function secret(name) {
  if (process.env[name]) return process.env[name]
  try {
    const envContent = await fs.readFile(path.join(repo, '.env.localnet'), 'utf8').catch(() => fs.readFile(path.join(repo, '.env'), 'utf8'))
    const match = envContent.match(new RegExp(`^\\s*(?:export\\s+)?${name}\\s*=\\s*(.+?)\\s*$`, 'm'))
    if (!match) return undefined
    const value = match[1].trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      return value.slice(1, -1)
    }
    return value.replace(/\s+#.*$/, '')
  } catch {
    return undefined
  }
}

async function producerKey() {
  return secret('PULSEVM_PRODUCER_KEY')
}

function parseUnits(asset, precision) {
  const decimal = asset.split(' ')[0]
  const [whole, fractional = ''] = decimal.split('.')
  return BigInt(whole) * (10n ** BigInt(precision)) + BigInt(fractional.padEnd(precision, '0').slice(0, precision) || '0')
}

function formatUnits(units, symbol, precision) {
  const scale = 10n ** BigInt(precision)
  return `${(units / scale).toString()}.${(units % scale).toString().padStart(precision, '0')} ${symbol}`
}

const rpc = new JsonRpc(RPC_URL)

async function waitFor(description, check, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs
  let attempts = 0
  while (Date.now() < deadline) {
    attempts++
    try {
      if (await check()) return
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
  throw new Error(`Timed out waiting for ${description} (${attempts} attempts over ${timeoutMs}ms)`)
}

async function getBalance(contract, account, symbol) {
  const rows = await rpc.get_currency_balance(contract, account, symbol)
  return rows[0] || `0.${'0'.repeat(4)} ${symbol}`
}

async function getTreasuryTokens() {
  const { rows } = await rpc.get_table_rows({
    json: true,
    code: TREASURY,
    scope: TREASURY,
    table: 'tokens',
    limit: 100,
  })
  return rows
}

async function main() {
  const endpoint = new URL(RPC_URL)
  if (!['127.0.0.1', 'localhost', '::1'].includes(endpoint.hostname)) {
    throw new Error('Refusing a non-loopback PulseVM RPC')
  }

  console.log('\n=== PulseVM Metal Dollar E2E Test (Collateral Only) ===\n')
  console.log('⚠️  Collateral-only test mode (XMD token issue detected).')
  console.log('    Testing wallet, RPC, and transaction signing with XUSDC transfers.\n')

  // Step 1: Validate local chain
  console.log('1️⃣  Connecting to local chain...')
  const info = await rpc.get_info()
  console.log(`   ✓ Connected to chain ${info.chain_id.slice(0, 16)}...`)

  // Step 2: Load keys
  console.log('\n2️⃣  Loading signing keys...')
  const userKey = await secret('WEBAUTH_PKEY')
  const producerKeyValue = await producerKey()
  if (!userKey || !producerKeyValue) {
    throw new Error('Set WEBAUTH_PKEY and PULSEVM_PRODUCER_KEY in .env.localnet or the environment')
  }
  const signatures = new JsSignatureProvider([producerKeyValue, userKey])
  const api = new Api({ rpc, signatureProvider: signatures, textDecoder: new TextDecoder(), textEncoder: new TextEncoder() })
  const publicKeys = await signatures.getAvailableKeys()
  console.log(`   ✓ Loaded WebAuth and producer keys`)

  // Step 3: Verify accounts exist
  console.log('\n3️⃣  Verifying accounts exist...')
  const accountNames = [USER, TREASURY, COLLATERAL_TOKEN]
  for (const name of accountNames) {
    try {
      await rpc.get_account(name)
      console.log(`   ✓ ${name}`)
    } catch {
      throw new Error(`Account ${name} does not exist. Run setup-webauth-e2e.mjs first.`)
    }
  }

  // Step 4: Verify contracts are deployed
  console.log('\n4️⃣  Verifying contracts are deployed...')
  const contracts = [
    { name: TREASURY, tables: ['tokens'] },
    { name: COLLATERAL_TOKEN, tables: ['stat'] },
  ]
  for (const contract of contracts) {
    const codeHash = await rpc.fetch('/v1/chain/get_code_hash', { account_name: contract.name })
    if (!codeHash?.code_hash || /^0+$/.test(codeHash.code_hash)) {
      throw new Error(`Contract ${contract.name} not deployed. Run setup-webauth-e2e.mjs first.`)
    }
    console.log(`   ✓ ${contract.name}`)
  }

  // Step 5: Fetch collateral list (UI simulation)
  console.log('\n5️⃣  Fetching collateral list from treasury...')
  const treasuryTokens = await getTreasuryTokens()
  if (treasuryTokens.length === 0) {
    throw new Error('No collateral tokens configured in treasury')
  }
  console.log(`   ✓ Found ${treasuryTokens.length} collateral(s):`)
  for (const token of treasuryTokens) {
    const symbol = token.symbol.sym.split(',')[1]
    console.log(`     - ${symbol} from ${token.symbol.contract}`)
  }

  // Step 6: Check user wallet state
  console.log('\n6️⃣  Checking user wallet state...')
  const userCollateral = await getBalance(COLLATERAL_TOKEN, USER, 'XUSDC')
  const treasuryCollateral = await getBalance(COLLATERAL_TOKEN, TREASURY, 'XUSDC')
  console.log(`   ✓ User ${USER}:`)
  console.log(`     - XUSDC: ${userCollateral}`)
  console.log(`   ✓ Treasury ${TREASURY}:`)
  console.log(`     - XUSDC: ${treasuryCollateral}`)

  // Step 7: Execute transfer to treasury (simulating mint deposit)
  console.log('\n7️⃣  Executing collateral transfer (simulating mint deposit)...')
  const collateralPrecision = 4
  const transferAmount = '10.0000 XUSDC'

  const beforeTransfer = {
    userCollateral: parseUnits(userCollateral, collateralPrecision),
    treasuryCollateral: parseUnits(treasuryCollateral, collateralPrecision),
  }

  const blockInfo = await rpc.get_info()
  const prefix = Number.parseInt(blockInfo.head_block_id.slice(16, 24).match(/../g).reverse().join(''), 16)
  const expiration = new Date(Date.now() + 120_000).toISOString().slice(0, 19)

  const transferTxResult = await api.transact(
    {
      actions: [{
        account: COLLATERAL_TOKEN,
        name: 'transfer',
        authorization: [{ actor: USER, permission: 'active' }],
        data: { from: USER, to: TREASURY, quantity: transferAmount, memo: 'deposit' },
      }],
    },
    {
      transactionHeader: {
        expiration,
        ref_block_num: blockInfo.head_block_num & 0xffff,
        ref_block_prefix: prefix,
        max_net_usage_words: 0,
        max_cpu_usage_ms: 0,
        delay_sec: 0,
      },
    },
  )
  console.log(`   ✓ Transfer transaction submitted: ${transferTxResult.transaction_id.slice(0, 16)}...`)

  // Step 8: Wait for transfer to settle and verify
  console.log('\n8️⃣  Verifying transfer settlement...')
  await waitFor('transfer to settle', async () => {
    const newUserCollateral = parseUnits(await getBalance(COLLATERAL_TOKEN, USER, 'XUSDC'), collateralPrecision)
    return newUserCollateral < beforeTransfer.userCollateral
  })

  const afterTransfer = {
    userCollateral: parseUnits(await getBalance(COLLATERAL_TOKEN, USER, 'XUSDC'), collateralPrecision),
    treasuryCollateral: parseUnits(await getBalance(COLLATERAL_TOKEN, TREASURY, 'XUSDC'), collateralPrecision),
  }

  const collateralSent = beforeTransfer.userCollateral - afterTransfer.userCollateral
  const collateralReceived = afterTransfer.treasuryCollateral - beforeTransfer.treasuryCollateral

  console.log(`   ✓ User sent ${formatUnits(collateralSent, 'XUSDC', collateralPrecision)}`)
  console.log(`   ✓ Treasury received ${formatUnits(collateralReceived, 'XUSDC', collateralPrecision)}`)

  if (collateralSent !== parseUnits(transferAmount, collateralPrecision)) {
    throw new Error(`Unexpected collateral amount transferred: expected ${transferAmount}, got ${formatUnits(collateralSent, 'XUSDC', collateralPrecision)}`)
  }

  // Step 9: Execute return transfer (simulating redemption)
  console.log('\n9️⃣  Executing collateral return (simulating redemption)...')
  const returnAmount = '5.0000 XUSDC'

  const beforeReturn = afterTransfer

  const returnTxResult = await api.transact(
    {
      actions: [{
        account: COLLATERAL_TOKEN,
        name: 'transfer',
        authorization: [{ actor: TREASURY, permission: 'active' }],
        data: { from: TREASURY, to: USER, quantity: returnAmount, memo: 'redeem' },
      }],
    },
    {
      transactionHeader: {
        expiration: new Date(Date.now() + 120_000).toISOString().slice(0, 19),
        ref_block_num: (await rpc.get_info()).head_block_num & 0xffff,
        ref_block_prefix: Number.parseInt((await rpc.get_info()).head_block_id.slice(16, 24).match(/../g).reverse().join(''), 16),
        max_net_usage_words: 0,
        max_cpu_usage_ms: 0,
        delay_sec: 0,
      },
    },
  )
  console.log(`   ✓ Return transaction submitted: ${returnTxResult.transaction_id.slice(0, 16)}...`)

  // Step 10: Wait for return to settle and verify
  console.log('\n🔟  Verifying return settlement...')
  await waitFor('return to settle', async () => {
    const newUserCollateral = parseUnits(await getBalance(COLLATERAL_TOKEN, USER, 'XUSDC'), collateralPrecision)
    return newUserCollateral > beforeReturn.userCollateral
  })

  const afterReturn = {
    userCollateral: parseUnits(await getBalance(COLLATERAL_TOKEN, USER, 'XUSDC'), collateralPrecision),
    treasuryCollateral: parseUnits(await getBalance(COLLATERAL_TOKEN, TREASURY, 'XUSDC'), collateralPrecision),
  }

  const collateralReturned = afterReturn.userCollateral - beforeReturn.userCollateral

  console.log(`   ✓ User received ${formatUnits(collateralReturned, 'XUSDC', collateralPrecision)}`)

  if (collateralReturned !== parseUnits(returnAmount, collateralPrecision)) {
    throw new Error(`Unexpected return amount: expected ${returnAmount}, got ${formatUnits(collateralReturned, 'XUSDC', collateralPrecision)}`)
  }

  // Step 11: Final state verification
  console.log('\n✅  Final State Summary:')
  console.log(`    User ${USER}:`)
  console.log(`      - XUSDC: ${formatUnits(afterReturn.userCollateral, 'XUSDC', collateralPrecision)}`)
  console.log(`    Treasury ${TREASURY}:`)
  console.log(`      - XUSDC: ${formatUnits(afterReturn.treasuryCollateral, 'XUSDC', collateralPrecision)}`)

  console.log('\n✨ End-to-end collateral transfer test PASSED\n')
  console.log('📋 Infrastructure Verified:')
  console.log('   ✓ Wallet authentication (WebAuth keys)')
  console.log('   ✓ RPC connectivity')
  console.log('   ✓ Transaction signing')
  console.log('   ✓ State queries (UI integration ready)')
  console.log('   ✓ Token operations (collateral transfers)')
  console.log('\n⚠️  Note: Full treasury mint/redeem with XMD requires fixing the XMD token stat row.')
  console.log('   See E2E_WORKAROUND.md for paths to resolve.')
}

main().catch((error) => {
  console.error(`\n❌ Test FAILED: ${error?.message || String(error)}\n`)
  process.exitCode = 1
})
