
use std::fs::copy;
use tempdir::TempDir;

pub fn setup_tracing() {
    // dropping error as many tests can setup_tracing

    let _ = tracing::subscriber::set_global_default(
        tracing_fmt::FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    );

    let _ = tracing_log::LogTracer::init();
}

pub fn setup_cache() -> TempDir {
    let tempdir = TempDir::new("tor-cache").expect("create temp dir");

    copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tools/directory-cache/authority.txt"),
        tempdir.path().join("authority.txt"),
    )
    .expect("copy temp authority file");

    copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tools/directory-cache/certificate.txt"),
        tempdir.path().join("certificate.txt"),
    )
    .expect("copy temp certificate file");

    copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tools/directory-cache/consensus.txt"),
        tempdir.path().join("consensus.txt"),
    )
    .expect("copy temp consensus file");

    copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tools/directory-cache/microdescriptors.txt"),
        tempdir.path().join("microdescriptors.txt"),
    )
    .expect("copy temp microdescriptors file");

    tempdir
}
