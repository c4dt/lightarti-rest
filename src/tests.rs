pub fn setup_tracing() {
    let subscriber = tracing_fmt::FmtSubscriber::builder()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("to be the only logger");
}
