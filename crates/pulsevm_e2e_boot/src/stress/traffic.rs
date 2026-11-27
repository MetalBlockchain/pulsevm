//! Transaction generators and the model of what the chain should hold after
//! every `Expect::Included` transaction has been applied.
//!
//! The workloads are chosen so the end state does not depend on the order
//! transactions reach a block, which is the one thing concurrent submission
//! through five nodes cannot control:
//!
//! * token transfers are commutative, and every account is funded far above anything it can send,
//!   so no transfer can fail for lack of funds;
//! * oracle writes are last-writer-wins by an explicit `seq`, so the highest `seq` per feeder wins
//!   however the writes interleave;
//! * AMM swaps are order-dependent, so only invariants are modelled (value conservation, `k` never
//!   shrinking, the swap count).
//!
//! The model is updated when a job is *generated*, never from observed results.
//! If the chain drops, duplicates or reorders something it should not have, the
//! Go test sees the divergence between model and chain.

use std::{
    collections::BTreeMap,
    str::FromStr,
    sync::Arc,
};

use anyhow::{
    Context,
    Result,
};
use pulsevm_core::{
    ACTIVE_NAME,
    PULSE_NAME,
    asset::Asset,
    authority::{
        Authority,
        KeyWeight,
        PermissionLevel,
    },
    config::NEWACCOUNT_NAME,
    crypto::PrivateKey,
    mempool::DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS,
    name::Name,
    pulse_contract::NewAccount,
    time::TimePointSec,
    transaction::{
        Action,
        PackedTransaction,
        SignedTransaction,
        Transaction,
    },
};
use pulsevm_proc_macros::{
    NumBytes,
    Read,
    Write,
};
use pulsevm_serialization::Write as _;

use crate::{
    contracts::{
        self,
        pack_u64s,
    },
    runner::{
        Ctx,
        Expect,
        Job,
    },
};

pub const TOKEN: &str = "pulse.token";
pub const CREATOR: &str = "test";
pub const SYM_A: &str = "PULSE";
pub const SYM_B: &str = "USDX";

/// Per-user starting balance of each token, in 1e-4 units (1000.0000).
pub const FUND_UNITS: i64 = 10_000_000;
/// PULSE the router holds to pay out of. It is funded from the issuer's slack
/// above the per-user funding (see `setup` in main.rs).
pub const ROUTER_FLOAT_UNITS: i64 = 2_000_000;
/// Per-user play-money credit in the AMM ledger, for each side.
pub const FAUCET_UNITS: u64 = 2_000_000;
pub const AMM_RESERVE: u64 = 1_000_000_000;
pub const PAIRS: [&str; 3] = ["btcusd", "ethusd", "hotpair"];
pub const HOT_PAIR: &str = "hotpair";

#[derive(Debug, Clone, Read, Write, NumBytes)]
struct TransferToken {
    from: Name,
    to: Name,
    quantity: Asset,
    memo: String,
}

/// splitmix64: tiny, seedable and good enough to shuffle a workload. A fixed
/// seed makes a failing run reproducible.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    /// Uniform in `[lo, hi]`.
    pub fn between(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}

pub struct User {
    pub name: Name,
    pub key: PrivateKey,
}

/// Index 0 of a balance pair is `PULSE`, index 1 is `USDX`.
#[derive(Default)]
pub struct Model {
    pub balances: BTreeMap<String, [i64; 2]>,
    pub supply: [i64; 2],
    pub amm_faucet: u64,
    pub amm_swaps: u64,
    pub amm_traders: Vec<String>,
    pub oracle_updates: u64,
    /// (pair, feeder) -> (price, seq) of the newest write.
    pub feeds: BTreeMap<(String, String), (u64, u64)>,
    seqs: BTreeMap<(String, String), u64>,
}

impl Model {
    fn transfer(&mut self, sym: usize, from: &str, to: &str, units: i64) {
        self.balances.entry(from.to_string()).or_default()[sym] -= units;
        self.balances.entry(to.to_string()).or_default()[sym] += units;
    }

    fn setprice(&mut self, pair: &str, feeder: &str, price: u64, seq: u64) {
        self.oracle_updates += 1;
        let slot = self
            .feeds
            .entry((pair.to_string(), feeder.to_string()))
            .or_insert((price, seq));
        if seq > slot.1 {
            *slot = (price, seq);
        }
    }

    fn next_seq(&mut self, pair: &str, feeder: &str) -> u64 {
        let seq = self
            .seqs
            .entry((pair.to_string(), feeder.to_string()))
            .or_default();
        *seq += 1;
        *seq
    }

    pub fn aggregate_for(&self, pair: &str) -> (u64, u64) {
        self.feeds
            .iter()
            .filter(|((p, _), _)| p == pair)
            .fold((0, 0), |(sum, count), (_, (price, _))| {
                (sum + price, count + 1)
            })
    }
}

pub struct World {
    pub ctx: Arc<Ctx>,
    pub users: Vec<User>,
    pub model: Model,
    pub rng: Rng,
    pub feeders: usize,
    token: Name,
    amm: Name,
    oracle: Name,
    router: Name,
    /// Recent good transactions, kept so some can be replayed as duplicates.
    recent: Vec<PackedTransaction>,
}

fn name(s: &str) -> Result<Name> {
    Name::from_str(s).map_err(|e| anyhow::anyhow!("encoding name {s}: {e}"))
}

/// Signs `actions` with every key in `signers` (in order) and packs the result.
pub fn build_tx(
    chain_id: &pulsevm_core::id::Id,
    actions: Vec<Action>,
    signers: &[&PrivateKey],
    expiration: TimePointSec,
) -> Result<PackedTransaction> {
    let mut transaction = Transaction::default();
    transaction.header.expiration = expiration;
    transaction.actions = actions;
    let mut signed = SignedTransaction::new(transaction, Vec::new(), vec![]);
    for key in signers {
        signed = signed
            .sign(key, chain_id)
            .map_err(|e| anyhow::anyhow!("signing transaction: {e}"))?;
    }
    PackedTransaction::from_signed_transaction(signed)
        .map_err(|e| anyhow::anyhow!("packing transaction: {e}"))
}

/// 12-character `a-z1-5` account name derived from an index.
fn user_name(mut index: usize) -> Result<Name> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz12345";
    let mut suffix = [b'a'; 11];
    for c in suffix.iter_mut().rev() {
        *c = CHARS[index % CHARS.len()];
        index /= CHARS.len();
    }
    name(&format!("u{}", std::str::from_utf8(&suffix)?))
}

pub fn asset(units: i64, symbol: &str) -> Result<Asset> {
    Asset::from_str(&format!(
        "{}.{:04} {symbol}",
        units / 10_000,
        units % 10_000
    ))
    .map_err(|e| anyhow::anyhow!("building asset {units} {symbol}: {e}"))
}

fn action(account: Name, action: &str, actor: Name, data: Vec<u8>) -> Result<Action> {
    Ok(Action::new(
        account,
        name(action)?,
        data,
        vec![PermissionLevel::new(actor.as_u64(), ACTIVE_NAME.as_u64())],
    ))
}

impl World {
    pub fn new(ctx: Arc<Ctx>, users: usize, seed: u64) -> Result<Self> {
        let feeders = 24.min(users.saturating_sub(1));
        let users = (0..users)
            .map(|i| {
                Ok(User {
                    name: user_name(i)?,
                    key: PrivateKey::random(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            ctx,
            users,
            model: Model::default(),
            rng: Rng::new(seed),
            feeders,
            token: name(TOKEN)?,
            amm: name(contracts::AMM)?,
            oracle: name(contracts::ORACLE)?,
            router: name(contracts::ROUTER)?,
            recent: Vec::new(),
        })
    }

    // ---- building blocks ---------------------------------------------------

    pub fn build(
        &self,
        actions: Vec<Action>,
        signers: &[&PrivateKey],
    ) -> Result<PackedTransaction> {
        self.build_expiring(
            actions,
            signers,
            TimePointSec::now() + DEFAULT_MEMPOOL_TRANSACTION_TTL_SECS,
        )
    }

    fn build_expiring(
        &self,
        actions: Vec<Action>,
        signers: &[&PrivateKey],
        expiration: TimePointSec,
    ) -> Result<PackedTransaction> {
        build_tx(&self.ctx.chain_id, actions, signers, expiration)
    }

    fn memo(&self, tag: &str) -> String {
        format!("{tag}{}", self.ctx.nonce())
    }

    fn transfer_data(
        &self,
        from: Name,
        to: Name,
        sym: &str,
        units: i64,
        memo: String,
    ) -> Result<Vec<u8>> {
        TransferToken {
            from,
            to,
            quantity: asset(units, sym)?,
            memo,
        }
        .pack()
        .context("packing transfer")
    }

    fn transfer_action(
        &self,
        from: Name,
        to: Name,
        sym: &str,
        units: i64,
        memo: String,
    ) -> Result<Action> {
        action(
            self.token,
            "transfer",
            from,
            self.transfer_data(from, to, sym, units, memo)?,
        )
    }

    fn swap_action(&self, trader: usize, dir: u64, amount_in: u64, min_out: u64) -> Result<Action> {
        let who = self.users[trader].name;
        action(
            self.amm,
            "swap",
            who,
            pack_u64s(&[who.as_u64(), dir, amount_in, min_out, self.ctx.nonce()]),
        )
    }

    fn two_users(&mut self) -> (usize, usize) {
        let a = self.rng.below(self.users.len());
        let mut b = self.rng.below(self.users.len());
        if b == a {
            b = (b + 1) % self.users.len();
        }
        (a, b)
    }

    fn remember(&mut self, tx: &PackedTransaction) {
        if self.recent.len() >= 64 {
            let drop_at = self.rng.below(self.recent.len());
            self.recent.swap_remove(drop_at);
        }
        self.recent.push(tx.clone());
    }

    fn good(&mut self, kind: &'static str, tx: PackedTransaction) -> Job {
        self.remember(&tx);
        Job {
            kind,
            expect: Expect::Included,
            tx,
        }
    }

    fn bad(kind: &'static str, tx: PackedTransaction) -> Job {
        Job {
            kind,
            expect: Expect::Never,
            tx,
        }
    }

    // ---- individual good transactions (each updates the model) -------------

    fn token_transfer(&mut self, kind: &'static str, sym: usize) -> Result<Job> {
        let (a, b) = self.two_users();
        let units = self.rng.between(1, 50) as i64;
        let symbol = if sym == 0 { SYM_A } else { SYM_B };
        let (from, to) = (self.users[a].name, self.users[b].name);
        let memo = self.memo("t");
        let tx = self.build(
            vec![self.transfer_action(from, to, symbol, units, memo)?],
            &[&self.users[a].key],
        )?;
        self.model
            .transfer(sym, &from.to_string(), &to.to_string(), units);
        Ok(self.good(kind, tx))
    }

    fn router_pay(&mut self) -> Result<Job> {
        let (a, b) = self.two_users();
        let units = self.rng.between(1, 30) as i64;
        let (from, to) = (self.users[a].name, self.users[b].name);
        let memo = self.memo("r");
        let data = self.transfer_data(from, to, SYM_A, units, memo)?;
        let tx = self.build(
            vec![action(self.router, "pay", from, data)?],
            &[&self.users[a].key],
        )?;
        // The router pays from its own balance; the caller only authorises.
        self.model
            .transfer(0, contracts::ROUTER, &to.to_string(), units);
        Ok(self.good("router_pay", tx))
    }

    fn amm_swap(&mut self, trader: usize) -> Result<Job> {
        let dir = self.rng.below(2) as u64;
        let amount = self.rng.between(100, 5_000);
        let tx = self.build(
            vec![self.swap_action(trader, dir, amount, 0)?],
            &[&self.users[trader].key],
        )?;
        self.model.amm_swaps += 1;
        Ok(self.good("amm_swap", tx))
    }

    fn oracle_write(&mut self, feeder: usize, pair: &str) -> Result<Job> {
        let who = self.users[feeder].name;
        let price = self.rng.between(1_000, 9_000_000);
        let seq = self.model.next_seq(pair, &who.to_string());
        let data = pack_u64s(&[
            who.as_u64(),
            name(pair)?.as_u64(),
            price,
            seq,
            self.ctx.nonce(),
        ]);
        let tx = self.build(
            vec![action(self.oracle, "setprice", who, data)?],
            &[&self.users[feeder].key],
        )?;
        self.model.setprice(pair, &who.to_string(), price, seq);
        Ok(self.good("oracle_setprice", tx))
    }

    /// One transaction, three actions: two token transfers and a swap, all
    /// authorised by the same account.
    fn bundle(&mut self) -> Result<Job> {
        let (a, b) = self.two_users();
        let mut c = self.rng.below(self.users.len());
        while c == a || c == b {
            c = (c + 1) % self.users.len();
        }
        let (from, p, q) = (self.users[a].name, self.users[b].name, self.users[c].name);
        let (u1, u2) = (
            self.rng.between(1, 40) as i64,
            self.rng.between(1, 40) as i64,
        );
        let swap_in = self.rng.between(100, 2_000);
        let (m1, m2) = (self.memo("b"), self.memo("b"));
        let actions = vec![
            self.transfer_action(from, p, SYM_A, u1, m1)?,
            self.transfer_action(from, q, SYM_B, u2, m2)?,
            self.swap_action(a, 0, swap_in, 0)?,
        ];
        let tx = self.build(actions, &[&self.users[a].key])?;
        self.model
            .transfer(0, &from.to_string(), &p.to_string(), u1);
        self.model
            .transfer(1, &from.to_string(), &q.to_string(), u2);
        self.model.amm_swaps += 1;
        Ok(self.good("bundle", tx))
    }

    /// An over-the-counter swap of the two real tokens between two parties in a
    /// single atomic transaction that needs both of their signatures.
    fn otc_swap(&mut self) -> Result<Job> {
        let (a, b) = self.two_users();
        let (pa, pb) = (self.users[a].name, self.users[b].name);
        let (give, take) = (
            self.rng.between(1, 60) as i64,
            self.rng.between(1, 60) as i64,
        );
        let (m1, m2) = (self.memo("o"), self.memo("o"));
        let actions = vec![
            self.transfer_action(pa, pb, SYM_A, give, m1)?,
            self.transfer_action(pb, pa, SYM_B, take, m2)?,
        ];
        let tx = self.build(actions, &[&self.users[a].key, &self.users[b].key])?;
        self.model
            .transfer(0, &pa.to_string(), &pb.to_string(), give);
        self.model
            .transfer(1, &pb.to_string(), &pa.to_string(), take);
        Ok(self.good("otc_swap", tx))
    }

    // ---- transactions that must never land ---------------------------------

    fn atomic_fail(&mut self) -> Result<Job> {
        let (a, b) = self.two_users();
        let (from, to) = (self.users[a].name, self.users[b].name);
        let memo = self.memo("x");
        let actions = vec![
            self.transfer_action(from, to, SYM_A, 7, memo)?,
            // The transfer above succeeds, then this swap's slippage guard
            // aborts. The transfer must roll back with it.
            self.swap_action(a, 0, 1_000, u64::MAX)?,
        ];
        Ok(Self::bad(
            "atomic_fail",
            self.build(actions, &[&self.users[a].key])?,
        ))
    }

    fn bad_traffic(&mut self, roll: u64) -> Result<Job> {
        let (a, b) = self.two_users();
        let (from, to) = (self.users[a].name, self.users[b].name);
        let memo = self.memo("x");
        let job = match roll % 8 {
            0 => {
                // Authority claimed for `from`, but signed by someone else.
                let tx = self.build(
                    vec![self.transfer_action(from, to, SYM_A, 1, memo)?],
                    &[&self.users[b].key],
                )?;
                Self::bad("bad_signature", tx)
            }
            1 => {
                let tx = self.build(
                    vec![self.transfer_action(from, to, SYM_A, 900_000_000_000, memo)?],
                    &[&self.users[a].key],
                )?;
                Self::bad("overdraw", tx)
            }
            2 => {
                let past = TimePointSec::new(TimePointSec::now().utc_seconds.saturating_sub(120));
                let tx = self.build_expiring(
                    vec![self.transfer_action(from, to, SYM_A, 1, memo)?],
                    &[&self.users[a].key],
                    past,
                )?;
                Self::bad("expired", tx)
            }
            3 => {
                let data = pack_u64s(&[from.as_u64(), self.ctx.nonce()]);
                let tx = self.build(
                    vec![action(name("ghostacct")?, "poke", from, data)?],
                    &[&self.users[a].key],
                )?;
                Self::bad("unknown_contract", tx)
            }
            4 => {
                // Names `to` as the authorizer of a transfer out of `from`.
                let data = self.transfer_data(from, to, SYM_A, 1, memo)?;
                let wrong = action(self.token, "transfer", to, data)?;
                Self::bad(
                    "wrong_authority",
                    self.build(vec![wrong], &[&self.users[b].key])?,
                )
            }
            5 => Self::bad(
                "slippage",
                self.build(
                    vec![self.swap_action(a, 1, 500, u64::MAX)?],
                    &[&self.users[a].key],
                )?,
            ),
            6 => {
                let data = vec![1, 2, 3, 4, 5];
                Self::bad(
                    "malformed_router_call",
                    self.build(
                        vec![action(self.router, "pay", from, data)?],
                        &[&self.users[a].key],
                    )?,
                )
            }
            _ => {
                let long = "m".repeat(300);
                Self::bad(
                    "oversize_memo",
                    self.build(
                        vec![self.transfer_action(from, to, SYM_A, 1, long)?],
                        &[&self.users[a].key],
                    )?,
                )
            }
        };
        Ok(job)
    }

    // ---- waves -------------------------------------------------------------

    pub fn onboard(&mut self) -> Result<Vec<Job>> {
        let creator = name(CREATOR)?;
        let mut jobs = Vec::with_capacity(self.users.len());
        for user in &self.users {
            let authority = Authority::new(
                1,
                vec![KeyWeight::new(user.key.get_public_key().into_k1(), 1)],
                vec![],
                vec![],
            );
            let data = NewAccount {
                creator,
                name: user.name,
                owner: authority.clone(),
                active: authority,
            }
            .pack()
            .context("packing newaccount")?;
            let tx = self.build(
                vec![action_with(PULSE_NAME, NEWACCOUNT_NAME, creator, data)],
                &[&self.ctx.genesis_key],
            )?;
            jobs.push(Job {
                kind: "newaccount",
                expect: Expect::Included,
                tx,
            });
        }
        Ok(jobs)
    }

    pub fn fund(&mut self) -> Result<Vec<Job>> {
        let mut jobs = Vec::new();
        // The router pays everyone else out of its own float.
        let memo = self.memo("f");
        let tx = self.build(
            vec![self.transfer_action(self.token, self.router, SYM_A, ROUTER_FLOAT_UNITS, memo)?],
            &[&self.ctx.genesis_key],
        )?;
        self.model
            .transfer(0, TOKEN, contracts::ROUTER, ROUTER_FLOAT_UNITS);
        jobs.push(Job {
            kind: "fund_router",
            expect: Expect::Included,
            tx,
        });
        for i in 0..self.users.len() {
            let user = self.users[i].name;
            for (sym, kind) in [(SYM_A, "fund_pulse"), (SYM_B, "fund_usdx")] {
                let memo = self.memo("f");
                let tx = self.build(
                    vec![self.transfer_action(self.token, user, sym, FUND_UNITS, memo)?],
                    &[&self.ctx.genesis_key],
                )?;
                let idx = usize::from(sym == SYM_B);
                self.model
                    .transfer(idx, TOKEN, &user.to_string(), FUND_UNITS);
                jobs.push(Job {
                    kind,
                    expect: Expect::Included,
                    tx,
                });
            }
            let data = pack_u64s(&[user.as_u64(), FAUCET_UNITS, FAUCET_UNITS, self.ctx.nonce()]);
            let tx = self.build(
                vec![action(self.amm, "faucet", user, data)?],
                &[&self.users[i].key],
            )?;
            self.model.amm_faucet += FAUCET_UNITS;
            self.model.amm_traders.push(user.to_string());
            jobs.push(Job {
                kind: "amm_faucet",
                expect: Expect::Included,
                tx,
            });
        }
        self.rng.shuffle(&mut jobs);
        Ok(jobs)
    }

    /// Plain token transfers, meant to be sent at a fixed rate.
    pub fn steady(&mut self, count: usize) -> Result<Vec<Job>> {
        (0..count)
            .map(|_| self.token_transfer("transfer", 0))
            .collect()
    }

    /// Everything at once: transfers of both tokens, inline-dispatch router
    /// payments and AMM swaps from random accounts.
    pub fn burst(&mut self, count: usize) -> Result<Vec<Job>> {
        let mut jobs = Vec::with_capacity(count);
        for _ in 0..count {
            let roll = self.rng.below(100);
            jobs.push(if roll < 40 {
                self.token_transfer("transfer", 0)?
            } else if roll < 55 {
                self.token_transfer("transfer", 1)?
            } else if roll < 75 {
                self.router_pay()?
            } else {
                let trader = self.rng.below(self.users.len());
                self.amm_swap(trader)?
            });
        }
        Ok(jobs)
    }

    /// Every account hits the same three rows: the oracle counter, the AMM pool
    /// and one recipient's token balance.
    pub fn hot_key(&mut self) -> Result<Vec<Job>> {
        let mut jobs = Vec::new();
        for i in 0..self.users.len() {
            jobs.push(self.oracle_write(i, HOT_PAIR)?);
            jobs.push(self.amm_swap(i)?);
            let sink = self.users[0].name;
            if i != 0 {
                let from = self.users[i].name;
                let units = self.rng.between(1, 10) as i64;
                let memo = self.memo("h");
                let tx = self.build(
                    vec![self.transfer_action(from, sink, SYM_A, units, memo)?],
                    &[&self.users[i].key],
                )?;
                self.model
                    .transfer(0, &from.to_string(), &sink.to_string(), units);
                jobs.push(self.good("fan_in", tx));
            }
        }
        self.rng.shuffle(&mut jobs);
        Ok(jobs)
    }

    /// Feeders write interleaved, out-of-order prices to three pairs while
    /// other accounts run table-scanning aggregates over the live data.
    pub fn oracle(&mut self, updates_per_feeder: usize) -> Result<Vec<Job>> {
        let mut jobs = Vec::new();
        for feeder in 1..=self.feeders {
            for pair in PAIRS {
                for _ in 0..updates_per_feeder {
                    jobs.push(self.oracle_write(feeder, pair)?);
                }
            }
        }
        // Sequence numbers were handed out in generation order. Shuffling the
        // submissions makes stale writes routinely arrive after newer ones.
        self.rng.shuffle(&mut jobs);
        let aggregates = (jobs.len() / 20).max(10);
        for _ in 0..aggregates {
            let caller = self.rng.below(self.users.len());
            jobs.push(self.aggregate(caller, HOT_PAIR, "oracle_aggregate")?);
        }
        self.rng.shuffle(&mut jobs);
        Ok(jobs)
    }

    fn aggregate(&mut self, caller: usize, pair: &str, kind: &'static str) -> Result<Job> {
        let who = self.users[caller].name;
        let data = pack_u64s(&[who.as_u64(), name(pair)?.as_u64(), self.ctx.nonce()]);
        let tx = self.build(
            vec![action(self.oracle, "aggregate", who, data)?],
            &[&self.users[caller].key],
        )?;
        Ok(self.good(kind, tx))
    }

    /// Run after everything else has settled, so the result is exact.
    pub fn final_aggregates(&mut self) -> Result<Vec<Job>> {
        PAIRS
            .iter()
            .map(|pair| self.aggregate(0, pair, "final_aggregate"))
            .collect()
    }

    pub fn bundles(&mut self, bundles: usize, otc: usize, atomic_fail: usize) -> Result<Vec<Job>> {
        let mut jobs = Vec::new();
        for _ in 0..bundles {
            jobs.push(self.bundle()?);
        }
        for _ in 0..otc {
            jobs.push(self.otc_swap()?);
        }
        for _ in 0..atomic_fail {
            jobs.push(self.atomic_fail()?);
        }
        self.rng.shuffle(&mut jobs);
        Ok(jobs)
    }

    /// A weighted mix of everything above, plus invalid traffic and replays,
    /// all interleaved in one stream.
    pub fn chaos(&mut self, count: usize) -> Result<Vec<Job>> {
        let mut jobs = Vec::with_capacity(count);
        for _ in 0..count {
            let roll = self.rng.below(100);
            let job = match roll {
                0..=19 => self.token_transfer("transfer", 0)?,
                20..=27 => self.token_transfer("transfer", 1)?,
                28..=39 => self.router_pay()?,
                40..=51 => {
                    let trader = self.rng.below(self.users.len());
                    self.amm_swap(trader)?
                }
                52..=60 => self.otc_swap()?,
                61..=68 => self.bundle()?,
                69..=82 => {
                    let feeder = 1 + self.rng.below(self.feeders.max(1));
                    let pair = PAIRS[self.rng.below(PAIRS.len())];
                    self.oracle_write(feeder, pair)?
                }
                83..=85 if !self.recent.is_empty() => {
                    let tx = self.recent[self.rng.below(self.recent.len())].clone();
                    Job {
                        kind: "duplicate_resubmit",
                        expect: Expect::Resubmit,
                        tx,
                    }
                }
                _ => {
                    let roll = self.rng.next();
                    self.bad_traffic(roll)?
                }
            };
            jobs.push(job);
        }
        Ok(jobs)
    }

    /// Minimal transfers in bulk, to push one node's mempool to its limit.
    pub fn saturate(&mut self, count: usize) -> Result<Vec<Job>> {
        (0..count)
            .map(|_| self.token_transfer("saturate", 0))
            .collect()
    }
}

fn action_with(account: Name, action_name: Name, actor: Name, data: Vec<u8>) -> Action {
    Action::new(
        account,
        action_name,
        data,
        vec![PermissionLevel::new(actor.as_u64(), ACTIVE_NAME.as_u64())],
    )
}
