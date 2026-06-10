use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn main() {
    let source_root = emulebb_miniupnp_root();
    let miniupnpc_root = source_root.join("miniupnpc");
    let include_dir = miniupnpc_root.join("include");
    let src_dir = miniupnpc_root.join("src");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set"));

    assert_exists(&miniupnpc_root);
    assert_exists(&include_dir);
    assert_exists(&src_dir);

    generate_miniupnpcstrings(&miniupnpc_root, &out_dir);

    let mut build = cc::Build::new();
    build
        .include(&include_dir)
        .include(&src_dir)
        .include(&out_dir)
        .define("MINIUPNP_STATICLIB", None);

    if env::var("CARGO_CFG_WINDOWS").is_ok() {
        build
            .define("_WIN32_WINNT", Some("0x0501"))
            .define("_CRT_SECURE_NO_WARNINGS", None)
            .define("_WINSOCK_DEPRECATED_NO_WARNINGS", None);
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=iphlpapi");
    } else {
        build
            .define("MINIUPNPC_SET_SOCKET_TIMEOUT", None)
            .define("MINIUPNPC_GET_SRC_ADDR", None)
            .define("_BSD_SOURCE", None)
            .define("_DEFAULT_SOURCE", None);
        if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() != Some("macos") {
            build.define("_XOPEN_SOURCE", Some("600"));
        }
        if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("netbsd") {
            build.define("_NETBSD_SOURCE", None);
        }
    }

    if env::var("CARGO_CFG_TARGET_OS").ok().as_deref() == Some("macos") {
        build.define("_DARWIN_C_SOURCE", None);
    }

    for file in [
        "igd_desc_parse.c",
        "miniupnpc.c",
        "minixml.c",
        "minisoap.c",
        "minissdpc.c",
        "miniwget.c",
        "upnpcommands.c",
        "upnpdev.c",
        "upnpreplyparse.c",
        "upnperrors.c",
        "connecthostport.c",
        "portlistingparse.c",
        "receivedata.c",
        "addr_is_reserved.c",
    ] {
        build.file(src_dir.join(file));
    }

    println!("cargo:rerun-if-env-changed=MINIUPNP_ROOT");
    println!("cargo:rerun-if-changed={}", miniupnpc_root.display());

    build.compile("miniupnpc");
}

fn emulebb_miniupnp_root() -> PathBuf {
    if let Ok(value) = env::var("MINIUPNP_ROOT") {
        return PathBuf::from(value);
    }

    PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"))
        .join("..")
        .join("..")
        .join("..")
        .join("third_party")
        .join("emulebb-miniupnp")
}

fn assert_exists(path: &Path) {
    assert!(
        path.exists(),
        "required MiniUPnP path does not exist: {}",
        path.display()
    );
}

fn generate_miniupnpcstrings(miniupnpc_root: &Path, out_dir: &Path) {
    let template = fs::read_to_string(miniupnpc_root.join("miniupnpcstrings.h.cmake"))
        .expect("failed to read miniupnpcstrings.h.cmake");
    let version = fs::read_to_string(miniupnpc_root.join("VERSION"))
        .expect("failed to read miniupnpc VERSION")
        .trim()
        .to_string();
    let target_os = env::var("CARGO_CFG_TARGET_OS").ok();
    let os_string = match target_os.as_deref() {
        Some("windows") => "Windows",
        Some("macos") => "Darwin",
        Some("linux") => "Linux",
        Some(other) => other,
        None => "Unknown",
    };

    let rendered = template
        .replace("${CMAKE_SYSTEM_NAME}", os_string)
        .replace("${PROJECT_VERSION}", &version);

    fs::write(out_dir.join("miniupnpcstrings.h"), rendered)
        .expect("failed to write generated miniupnpcstrings.h");
}
