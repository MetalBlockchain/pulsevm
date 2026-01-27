mod io {
    pub mod prometheus {
        pub mod client {
            tonic::include_proto!("io.prometheus.client");
        }
    }
}

pub mod vm {
    tonic::include_proto!("vm");

    pub mod runtime {
        tonic::include_proto!("vm.runtime");
    }
}

pub mod appsender {
    tonic::include_proto!("appsender");
}

pub mod messenger {
    tonic::include_proto!("messenger");
}

pub mod http {
    tonic::include_proto!("http");
}
