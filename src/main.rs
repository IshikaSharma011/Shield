use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "shield",
    about = "Shield security framework demonstration",
    version
)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
    println!("{}", shield::welcome_message());
}
