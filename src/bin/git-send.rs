fn main() {
    if let Err(error) = git_porter::cli::client::run(false) {
        if !error.is::<git_porter::runtime::push_result::Reported>() {
            git_porter::cli::report_error("git-send", error);
        }
        std::process::exit(1);
    }
}
