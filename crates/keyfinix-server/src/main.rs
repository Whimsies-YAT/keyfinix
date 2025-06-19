use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[clap(
        short,
        long,
        default_value = "config.toml",
        help = "Path to the configuration file"
    )]
    config: String,

    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Parser, Default, Debug)]
enum SubCommand {
    #[clap(name = "serve", about = "Run the server", alias = "server")]
    #[default]
    Serve,
}

fn main() {
    #[cfg(all(target_family = "unix", not(debug_assertions)))]
    libc::prctl(libc::PR_SET_DUMPABLE, 0);

    keyfinix_server::log::initialize_global_logger(false);

    let cli = Cli::parse();
    println!("config: {}", cli.config);
    println!("subcommand: {:?}", cli.subcommand);
}
