use clap::Parser;

#[derive(Parser)]
#[command(name = "cachelane", version, about = "CacheLane command line tools")]
struct Cli {}

fn main() {
    Cli::parse();
    println!("CacheLane CLI is ready");
}
