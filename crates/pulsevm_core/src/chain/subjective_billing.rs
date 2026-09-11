use std::collections::HashMap;

use pulsevm_constants::RATE_LIMITING_PRECISION;

/// Node-local resource usage retained after a transaction is rolled back.
///
/// Failed input transactions cannot write their resource usage to consensus
/// state because they do not appear in the produced block. This ledger keeps
/// the charge local to the node that did the speculative work and applies the
/// same decay used by the chain resource accumulators.
#[derive(Default)]
pub(super) struct SubjectiveBilling {
    accounts: HashMap<u64, AccountBill>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct SubjectiveBill {
    pub cpu: u64,
    pub net: u64,
}

#[derive(Clone, Copy, Default)]
struct AccountBill {
    cpu: DecayingUsage,
    net: DecayingUsage,
}

#[derive(Clone, Copy, Default)]
struct DecayingUsage {
    value_ex: u64,
    last_ordinal: u32,
}

impl SubjectiveBilling {
    pub fn get_bill(
        &mut self,
        account: u64,
        ordinal: u32,
        cpu_window: u32,
        net_window: u32,
    ) -> SubjectiveBill {
        let Some(bill) = self.accounts.get_mut(&account) else {
            return SubjectiveBill::default();
        };

        let result = SubjectiveBill {
            cpu: bill.cpu.used_at(ordinal, cpu_window),
            net: bill.net.used_at(ordinal, net_window),
        };
        if result == SubjectiveBill::default() {
            self.accounts.remove(&account);
        }
        result
    }

    pub fn bill_failure(
        &mut self,
        account: u64,
        cpu_usage: u64,
        net_usage: u64,
        ordinal: u32,
        cpu_window: u32,
        net_window: u32,
    ) {
        let bill = self.accounts.entry(account).or_default();
        bill.cpu.add(cpu_usage, ordinal, cpu_window);
        bill.net.add(net_usage, ordinal, net_window);
    }

    pub fn clear(&mut self) {
        self.accounts.clear();
    }
}

impl DecayingUsage {
    fn decay_to(&mut self, ordinal: u32, window: u32) {
        let window = window.max(1);
        if self.value_ex == 0 {
            self.last_ordinal = ordinal;
            return;
        }
        if self.last_ordinal == ordinal {
            return;
        }

        // Block-timestamp slots are u32 and eventually wrap. A small wrapping
        // delta is forward progress across that boundary; a delta over half the
        // range is an older speculative timestamp and must not erase the bill.
        let delta = ordinal.wrapping_sub(self.last_ordinal);
        if delta > i32::MAX as u32 {
            return;
        }
        if delta >= window {
            self.value_ex = 0;
        } else {
            self.value_ex =
                ((self.value_ex as u128 * (window - delta) as u128) / window as u128) as u64;
        }
        self.last_ordinal = ordinal;
    }

    fn used_at(&mut self, ordinal: u32, window: u32) -> u64 {
        let window = window.max(1);
        self.decay_to(ordinal, window);
        divide_ceil(
            self.value_ex as u128 * window as u128,
            RATE_LIMITING_PRECISION as u128,
        )
        .min(u64::MAX as u128) as u64
    }

    fn add(&mut self, units: u64, ordinal: u32, window: u32) {
        let window = window.max(1);
        self.decay_to(ordinal, window);
        let contribution = divide_ceil(
            units as u128 * RATE_LIMITING_PRECISION as u128,
            window as u128,
        );
        self.value_ex = (self.value_ex as u128 + contribution).min(u64::MAX as u128) as u64;
    }
}

fn divide_ceil(num: u128, den: u128) -> u128 {
    num / den + u128::from(!num.is_multiple_of(den))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_bills_are_isolated_and_decay() {
        let mut billing = SubjectiveBilling::default();
        billing.bill_failure(7, 1_000, 400, 10, 100, 50);

        assert_eq!(
            billing.get_bill(7, 10, 100, 50),
            SubjectiveBill {
                cpu: 1_000,
                net: 400,
            }
        );
        assert_eq!(
            billing.get_bill(7, 35, 100, 50),
            SubjectiveBill { cpu: 750, net: 200 }
        );
        assert_eq!(billing.get_bill(8, 35, 100, 50), SubjectiveBill::default());
        assert_eq!(billing.get_bill(7, 135, 100, 50), SubjectiveBill::default());
    }

    #[test]
    fn repeated_failures_accumulate_for_the_same_authorizer() {
        let mut billing = SubjectiveBilling::default();
        billing.bill_failure(7, 100, 40, 10, 100, 100);
        billing.bill_failure(7, 200, 60, 10, 100, 100);

        assert_eq!(
            billing.get_bill(7, 10, 100, 100),
            SubjectiveBill { cpu: 300, net: 100 }
        );
    }
}
