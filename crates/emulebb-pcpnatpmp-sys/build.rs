use std::{
    env,
    path::{Path, PathBuf},
};

fn main() {
    let source_root = emulebb_pcpnatpmp_root();
    let lib_root = source_root.join("lib");
    let src_root = lib_root.join("src");
    let net_root = src_root.join("net");

    assert_exists(&lib_root);
    assert_exists(&lib_root.join("include").join("pcpnatpmp.h"));

    let mut build = cc::Build::new();
    build
        .include(lib_root.join("include"))
        .include(&lib_root)
        .include(&src_root)
        .include(&net_root)
        .define("PCP_MIN_SUPPORTED_VERSION", Some("0"))
        .define("PCP_MAX_SUPPORTED_VERSION", Some("2"))
        .define("PCP_SERVER_PORT", Some("5351"))
        .define("PCP_MAX_PING_COUNT", Some("3"))
        .define("PCP_SERVER_DISCOVERY_RETRY_DELAY", Some("3600"))
        .define("PCP_RETX_IRT", Some("1000"))
        .define("PCP_RETX_MRC", Some("3"))
        .define("PCP_RETX_MRT", Some("4000"))
        .define("PCP_RETX_MRD", Some("0"));

    if env::var("CARGO_CFG_WINDOWS").is_ok() {
        build
            .include(src_root.join("windows"))
            .include(source_root.join("win_utils"))
            .define("WIN32", None)
            .define("_CRT_SECURE_NO_WARNINGS", None);
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=iphlpapi");
        build.file(src_root.join("windows").join("pcp_gettimeofday.c"));
    }

    for file in [
        "net/gateway.c",
        "net/findsaddr-udp.c",
        "pcp_api.c",
        "pcp_client_db.c",
        "pcp_event_handler.c",
        "pcp_logger.c",
        "pcp_msg.c",
        "pcp_server_discovery.c",
        "net/sock_ntop.c",
        "net/pcp_socket.c",
    ] {
        build.file(src_root.join(file));
    }

    println!("cargo:rerun-if-env-changed=PCPNATPMP_ROOT");
    println!("cargo:rerun-if-changed={}", lib_root.display());
    build.compile("pcpnatpmp");
}

fn emulebb_pcpnatpmp_root() -> PathBuf {
    if let Ok(value) = env::var("PCPNATPMP_ROOT") {
        return PathBuf::from(value);
    }

    PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"))
        .join("..")
        .join("..")
        .join("..")
        .join("third_party")
        .join("emulebb-libpcpnatpmp")
}

fn assert_exists(path: &Path) {
    assert!(
        path.exists(),
        "required libpcpnatpmp path does not exist: {}",
        path.display()
    );
}
