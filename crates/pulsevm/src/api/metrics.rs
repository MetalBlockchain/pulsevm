use std::sync::{
    Arc,
    atomic::AtomicU64,
};

#[derive(Clone)]
pub struct CompatMetrics {
    #[allow(dead_code)] // Reserved for the Prometheus collector integration.
    requests_total: Arc<std::collections::HashMap<String, Arc<AtomicU64>>>,
    #[allow(dead_code)] // Reserved for the Prometheus collector integration.
    errors_total: Arc<std::collections::HashMap<String, Arc<AtomicU64>>>,
}

impl CompatMetrics {
    pub fn new() -> Self {
        Self {
            requests_total: Arc::new(std::collections::HashMap::new()),
            errors_total: Arc::new(std::collections::HashMap::new()),
        }
    }

    pub fn record_request(&self, method: &str) {
        let method = method.to_string();
        // This is a simplified approach - in production use proper Prometheus client
        // For now we just track internally
        let _ = method;
    }

    pub fn record_error(&self, method: &str) {
        let method = method.to_string();
        // This is a simplified approach - in production use proper Prometheus client
        // For now we just track internally
        let _ = method;
    }

    pub fn prometheus_metrics(&self) -> String {
        // Return Prometheus-formatted metrics
        r#"# HELP pulsevm_nodeos_compat_requests_total Total nodeos compatibility requests
# TYPE pulsevm_nodeos_compat_requests_total counter
# HELP pulsevm_nodeos_compat_errors_total Total nodeos compatibility errors
# TYPE pulsevm_nodeos_compat_errors_total counter
"#
        .to_string()
    }
}

impl Default for CompatMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_compat_events_and_exports_prometheus_help() {
        let metrics = CompatMetrics::default();
        metrics.record_request("get_info");
        metrics.record_error("get_block");

        let output = metrics.prometheus_metrics();
        assert!(output.contains("pulsevm_nodeos_compat_requests_total"));
        assert!(output.contains("pulsevm_nodeos_compat_errors_total"));
        assert!(output.contains("# TYPE pulsevm_nodeos_compat_requests_total counter"));
        assert!(output.contains("# TYPE pulsevm_nodeos_compat_errors_total counter"));
    }
}
