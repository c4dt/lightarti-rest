use std::fs::File;
use std::io::Write;
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

    let authority = include_str!("test-data/authority.txt");
    let certificate = include_str!("test-data/certificate.txt");
    let consensus = include_str!("test-data/consensus.txt");
    let microdescriptors = include_str!("test-data/microdescriptors.txt");

    let authority_path = tempdir.path().join("authority.txt");
    let mut authority_file = File::create(authority_path).expect("create temp authority file");
    write!(authority_file, "{}", authority).expect("write temp authority file");

    let certificate_path = tempdir.path().join("certificate.txt");
    let mut certificate_file = File::create(certificate_path).expect("create temp certificate file");
    write!(certificate_file, "{}", certificate).expect("write temp certificate file");

    let consensus_path = tempdir.path().join("consensus.txt");
    let mut consensus_file = File::create(consensus_path).expect("create temp consensus file");
    write!(consensus_file, "{}", consensus).expect("write temp consensus file");

    let microdescriptors_path = tempdir.path().join("microdescriptors.txt");
    let mut microdescriptors_file =
        File::create(microdescriptors_path).expect("create temp microdescriptors file");
    write!(microdescriptors_file, "{}", microdescriptors)
        .expect("write temp microdescriptors file");

    tempdir
}
