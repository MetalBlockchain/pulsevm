use std::{
    hint::black_box,
    num::NonZeroUsize,
};

use criterion::{
    BatchSize,
    BenchmarkId,
    Criterion,
    Throughput,
    criterion_group,
    criterion_main,
};
use pulsevm_database::{
    BlockReadSnapshot,
    ContractPrimaryKey,
    Database,
    SpeculativeCandidate,
    SpeculativeTask,
};
use pulsevm_error::ChainError;

const TASKS: usize = 64;
const WORK_ROUNDS: usize = 20_000;

#[derive(Clone, Copy)]
enum Scenario {
    Independent,
    Mixed,
    HotKey,
}

impl Scenario {
    const fn name(self) -> &'static str {
        match self {
            Self::Independent => "independent",
            Self::Mixed => "mixed_25pct_hot",
            Self::HotKey => "hot_key",
        }
    }

    const fn primary(self, index: usize) -> u64 {
        match self {
            Self::Independent => index as u64,
            Self::Mixed if index.is_multiple_of(4) => 0,
            Self::Mixed => index as u64,
            Self::HotKey => 0,
        }
    }
}

#[derive(Clone, Copy)]
struct CpuBoundUpdate {
    key: ContractPrimaryKey,
    salt: u64,
}

impl CpuBoundUpdate {
    fn next_value(&self, current: &[u8]) -> (u64, Vec<u8>) {
        let mut value = current
            .get(..8)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0);
        value = value.wrapping_add(1);
        let mut digest = value ^ self.salt;
        for round in 0..WORK_ROUNDS {
            digest = digest
                .rotate_left(7)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(round as u64);
        }
        black_box(digest);
        (value, value.to_le_bytes().to_vec())
    }
}

impl SpeculativeTask for CpuBoundUpdate {
    type Output = u64;

    fn speculate(
        &self,
        snapshot: BlockReadSnapshot,
    ) -> Result<SpeculativeCandidate<Self::Output>, ChainError> {
        let mut overlay = snapshot.transaction();
        let current = overlay
            .get(self.key)
            .map_err(|reason| {
                ChainError::DatabaseError(format!("benchmark snapshot became stale: {reason:?}"))
            })?
            .ok_or_else(|| {
                ChainError::DatabaseError("benchmark row disappeared during speculation".into())
            })?;
        let (output, bytes) = self.next_value(&current);
        overlay.update(self.key, 1, bytes)?;
        Ok(SpeculativeCandidate::new(overlay.finish(), output))
    }

    fn execute_serial(&self, database: &mut Database) -> Result<Self::Output, ChainError> {
        let current = database
            .arena_kv_get(
                self.key.code,
                self.key.scope,
                self.key.table,
                self.key.primary,
            )
            .ok_or_else(|| ChainError::DatabaseError("benchmark row disappeared".into()))?;
        let (output, bytes) = self.next_value(&current);
        database.update_key_value_object_standalone(
            self.key.code,
            self.key.scope,
            self.key.table,
            self.key.primary,
            1,
            &bytes,
        )?;
        Ok(output)
    }
}

fn workload(scenario: Scenario) -> Vec<CpuBoundUpdate> {
    (0..TASKS)
        .map(|index| CpuBoundUpdate {
            key: ContractPrimaryKey::new(1, 2, 3, scenario.primary(index)),
            salt: index as u64,
        })
        .collect()
}

fn seeded(tasks: &[CpuBoundUpdate]) -> Database {
    let database = Database::default();
    let mut primaries = tasks
        .iter()
        .map(|task| task.key.primary)
        .collect::<Vec<_>>();
    primaries.sort_unstable();
    primaries.dedup();
    for primary in primaries {
        database
            .create_key_value_object_standalone(1, 2, 3, 1, primary, &0u64.to_le_bytes())
            .unwrap();
    }
    database
}

fn execute_serial(database: &mut Database, tasks: &[CpuBoundUpdate]) {
    database.arena_start_undo_session();
    for task in tasks {
        database.arena_start_undo_session();
        task.execute_serial(database).unwrap();
        database.arena_squash();
    }
    database.arena_squash();
}

fn optimistic_execution(c: &mut Criterion) {
    for scenario in [Scenario::Independent, Scenario::Mixed, Scenario::HotKey] {
        let tasks = workload(scenario);
        let mut group = c.benchmark_group(format!("optimistic_execution/{}", scenario.name()));
        group.throughput(Throughput::Elements(TASKS as u64));

        group.bench_function("serial", |b| {
            b.iter_batched(
                || seeded(&tasks),
                |mut database| {
                    execute_serial(&mut database, &tasks);
                    black_box(database.arena_state_root());
                },
                BatchSize::SmallInput,
            );
        });

        for workers in [1usize, 2, 4, 8] {
            group.bench_with_input(
                BenchmarkId::new("optimistic", workers),
                &workers,
                |b, workers| {
                    b.iter_batched(
                        || seeded(&tasks),
                        |mut database| {
                            let result = database
                                .execute_speculative_batch(
                                    &tasks,
                                    NonZeroUsize::new(*workers).unwrap(),
                                )
                                .unwrap();
                            black_box(result.outputs());
                            black_box(result.outcomes());
                            black_box(result.waves());
                            black_box(database.arena_state_root());
                        },
                        BatchSize::SmallInput,
                    );
                },
            );
        }
        group.finish();
    }
}

criterion_group!(benches, optimistic_execution);
criterion_main!(benches);
