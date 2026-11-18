fn main() {
    if let Err(error) = git_porter::cli::admin::run() {
        if !error.is::<git_porter::runtime::push_result::Reported>() {
            git_porter::cli::report_error("git-porter", error);
        }
        std::process::exit(1);
    }
}
