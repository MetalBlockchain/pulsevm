enum TransactionStatus {
    Executed,
    SoftFail,
    HardFail,
}

pub struct TransactionReceiptHeader {
    status: TransactionStatus,
    cpu_usage_us: u32,
    net_usage_words: u32,
}
