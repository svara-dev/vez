use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let lib = pkg_config::Config::new()
        .probe("libsolv")
        .expect("libsolv not found via pkg-config (dnf install libsolv-devel / equivalent)");
    // `pool_parserpmrichdep` (rich/boolean dependency parsing, e.g. `(A if
    // B)`) lives in libsolvext, not libsolv itself.
    let ext_lib = pkg_config::Config::new()
        .probe("libsolvext")
        .expect("libsolvext not found via pkg-config (dnf install libsolv-devel / equivalent)");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // By default we use the committed `bindings.rs` in `generated/` instead
    // of running bindgen at build time. bindgen needs libclang (clang-devel),
    // and on EL10 the current clang-devel pulls a newer llvm-libs than the
    // distro's `rust` package is built against, so the two BuildRequires
    // can't be installed together. The libsolv API we use is small and
    // stable, so a vendored copy that's regenerated on demand (the
    // `regen-bindings` feature) is more portable and drops the build-time
    // libclang dependency.
    #[cfg(feature = "regen-bindings")]
    regen_bindings(&lib, &out_dir);
    #[cfg(not(feature = "regen-bindings"))]
    {
        let _ = &lib;
        fs::copy(
            manifest_dir.join("generated/bindings.rs"),
            out_dir.join("bindings.rs"),
        )
        .expect("failed to copy vendored bindings.rs");
    }

    // `generated/static_fns.c` is maintained by hand, NOT bindgen output. It
    // wraps only the `static inline` libsolv functions we call
    // (pool_id2solvable, queue_push2; see sys.rs) in non-inline
    // `<name>__extern` symbols, since static inline functions have no
    // linkable symbol in libsolv.so. We don't let bindgen's wrap_static_fns
    // generate this file: it emits a wrapper for every static inline function
    // in libsolv's headers, including ones we never call, and that set isn't
    // part of libsolv's stable ABI. EL10 ships libsolv 0.7.33, whose hash.h
    // lacks `allochashtable` (and others) that newer Fedora libsolv declares,
    // so a full generated dump failed to compile there with "implicit
    // declaration of function 'allochashtable'" even though we never call it.
    println!("cargo:rerun-if-changed=generated/static_fns.c");
    let mut build = cc::Build::new();
    build.file(manifest_dir.join("generated/static_fns.c"));
    build.include(&manifest_dir);
    for path in &lib.include_paths {
        build.include(path);
    }
    build.compile("vez_solv_inline_shims");

    for path in lib.link_paths.iter().chain(&ext_lib.link_paths) {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
    // libsolvext must come first: it depends on libsolv's symbols.
    for name in ext_lib.libs.iter().chain(&lib.libs) {
        println!("cargo:rustc-link-lib={name}");
    }
}

#[cfg(feature = "regen-bindings")]
fn regen_bindings(lib: &pkg_config::Library, out_dir: &PathBuf) {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // bindgen has an old limitation with libsolv's `struct s_Foo;` (forward
    // decl in pooltypes.h) followed by `typedef struct s_Foo { ... } Foo;`
    // (full definition in e.g. solvable.h): it emits an opaque `{ _address:
    // u8 }` stub instead of the real fields, even though clang's AST has the
    // complete type. We only touch
    // Pool/Repo/Repodata/Solver/Stringpool/Repokey/KeyValue through libsolv's
    // real (non-inline, linkable) accessor functions, so opaque is fine for
    // those. `Solvable` is the one type C callers (and we) read fields on
    // directly (name, arch, evr, repo), so we blocklist bindgen's broken
    // version here and hand-write the struct in `sys.rs`. Its layout is
    // small, stable, and part of libsolv's public ABI.
    //
    // wrap_static_fns is off on purpose: pool_id2solvable/queue_push2 (the
    // only static inline functions we call) are wrapped and declared by hand
    // in sys.rs/generated/static_fns.c, so this step only refreshes the
    // ordinary extern-fn/type bindings.
    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .layout_tests(false)
        .blocklist_type("s_Solvable")
        .blocklist_type("Solvable")
        .blocklist_function("pool_id2solvable")
        .blocklist_function("queue_push2")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for path in &lib.include_paths {
        builder = builder.clang_arg(format!("-I{}", path.display()));
    }

    let bindings = builder
        .generate()
        .expect("failed to generate libsolv bindings");
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("failed to write bindings.rs");

    fs::copy(
        out_dir.join("bindings.rs"),
        manifest_dir.join("generated/bindings.rs"),
    )
    .expect("failed to update vendored generated/bindings.rs");
}
