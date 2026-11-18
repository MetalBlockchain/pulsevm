//! Keeps the log readable when a node refuses blocks faster than anyone can
//! read, without dropping what it learned.
//!
//! A node that is behind sees every block of a peer that is ahead, each refused
//! because its parent is not known yet. Paul counted 1.3 million of those
//! warnings in two hours. They are not noise in the sense of being wrong, and
//! lowering their level would hide a real failure among them, so nothing is
//! hidden: the first refusal in a window is logged in full, the rest are counted,
//! and one summary per window says how many, over which heights, and why the first
//! was refused.

use std::time::Duration;

/// How long refusals are gathered before a summary is written.
pub const SUMMARY_WINDOW: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// First in its window: log this block's refusal in full.
    LogInFull,
    /// Counted into the window's summary.
    Counted,
}

#[derive(Debug, Default)]
pub struct RefusedBlocks {
    window_started_at: Option<Duration>,
    counted: u64,
    lowest: u32,
    highest: u32,
    first_reason: String,
}

impl RefusedBlocks {
    /// Record a refusal at `now` (time since any fixed start). Returns what to do
    /// with it, and the summary of the window that has just ended if there is one.
    pub fn note(&mut self, now: Duration, height: u32, reason: &str) -> (Refusal, Option<String>) {
        let summary = self.flush_if_due(now);
        match self.window_started_at {
            None => {
                self.window_started_at = Some(now);
                self.first_reason = reason.to_owned();
                (Refusal::LogInFull, summary)
            }
            Some(_) => {
                if self.counted == 0 {
                    self.lowest = height;
                    self.highest = height;
                } else {
                    self.lowest = self.lowest.min(height);
                    self.highest = self.highest.max(height);
                }
                self.counted += 1;
                (Refusal::Counted, summary)
            }
        }
    }

    /// The summary of the window if it has run its course. Called on a timer so a
    /// window that ends with nothing more refused is still reported.
    pub fn flush_if_due(&mut self, now: Duration) -> Option<String> {
        let started = self.window_started_at?;
        if now.saturating_sub(started) < SUMMARY_WINDOW {
            return None;
        }
        let summary = (self.counted > 0).then(|| {
            format!(
                "refused {} more block(s) above the accepted head in the last {}s (heights {} to {}); the first of the window was refused because: {}",
                self.counted,
                SUMMARY_WINDOW.as_secs(),
                self.lowest,
                self.highest,
                self.first_reason
            )
        });
        *self = Self::default();
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn the_first_refusal_is_logged_in_full_and_the_rest_are_counted() {
        let mut log = RefusedBlocks::default();
        assert_eq!(
            log.note(secs(0), 100, "parent unknown").0,
            Refusal::LogInFull
        );
        for height in 101..=120 {
            assert_eq!(
                log.note(secs(1), height, "parent unknown").0,
                Refusal::Counted
            );
        }
    }

    #[test]
    fn nothing_is_lost_the_summary_carries_the_count_range_and_reason() {
        let mut log = RefusedBlocks::default();
        log.note(secs(0), 100, "the parent of block 100 is unknown");
        for height in [105u32, 101, 140, 120] {
            log.note(secs(2), height, "ignored: only the first reason is kept");
        }
        let summary = log
            .flush_if_due(secs(10))
            .expect("the window has run its course");
        assert!(summary.contains("refused 4 more block(s)"), "{summary}");
        assert!(summary.contains("heights 101 to 140"), "{summary}");
        assert!(
            summary.contains("the parent of block 100 is unknown"),
            "{summary}"
        );
    }

    #[test]
    fn nothing_is_reported_before_the_window_ends() {
        let mut log = RefusedBlocks::default();
        log.note(secs(0), 1, "x");
        log.note(secs(1), 2, "x");
        assert_eq!(log.flush_if_due(secs(9)), None);
        assert!(log.flush_if_due(secs(10)).is_some());
    }

    #[test]
    fn a_new_window_starts_with_a_full_log_line() {
        let mut log = RefusedBlocks::default();
        log.note(secs(0), 1, "x");
        log.note(secs(3), 2, "x");
        let (decision, summary) = log.note(secs(11), 50, "later reason");
        assert!(summary.unwrap().contains("refused 1 more"));
        assert_eq!(decision, Refusal::LogInFull);
    }

    #[test]
    fn a_window_with_only_the_first_refusal_has_nothing_to_summarise() {
        let mut log = RefusedBlocks::default();
        log.note(secs(0), 1, "x");
        assert_eq!(log.flush_if_due(secs(11)), None, "it was logged in full");
        // And the next refusal opens a fresh window.
        assert_eq!(log.note(secs(12), 2, "y").0, Refusal::LogInFull);
    }

    #[test]
    fn no_refusals_means_no_summary() {
        let mut log = RefusedBlocks::default();
        assert_eq!(log.flush_if_due(secs(1000)), None);
    }
}
