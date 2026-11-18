fn main() {
    if let Err(error) = git_porter::cli::client::run(true) {
        git_porter::cli::report_error("git-receive", error);
        std::process::exit(1);
    }
}
