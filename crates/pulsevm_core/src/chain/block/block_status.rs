#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStatus {
    Building,
    Verifying,
    Accepting,
    Benchmarking, // Only used for benchmarking, not for actual block production
}
