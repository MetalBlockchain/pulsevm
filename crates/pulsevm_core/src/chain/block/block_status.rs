#[repr(u8)]
#[derive(Clone, Copy)]
pub enum BlockStatus {
    Building,
    Verifying,
    Accepting,
}
