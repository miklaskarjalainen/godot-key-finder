use clap::{Subcommand, Parser};

/// Simple program to brute-force the encryption key from a godot game,
/// by trying to use every possible 32-byte sequence in a binary to decrypt the contents.
/// This program is only meant as a proof of concept, and is only tested on godot 4.4.1.
/// Author: Miklas "Giffi" Karjalainen
#[derive(Parser, Debug)]
#[command(version, about, long_about = None, verbatim_doc_comment)]
pub struct Args {
    #[clap(subcommand)]
    pub cmd: CommandType,

    /// How many threads to use.
    #[arg(short, long, default_value_t = 1)]
    pub jobs: u8,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CommandPck {
    /// Path to the 'pck' file, which was encrypted with the encryption key.
    #[arg(short, long)]
    pub pck: String,
    /// Path to the binary file, which contains the encyrption key somewhere in it.
    #[arg(short, long)]
    pub bin: String,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct CommandEmbedded {
    /// Path to the binary file, with embedded & encrypted 'pck'. 
    #[arg(short, long)]
    pub bin: String,
}

#[derive(Debug, Subcommand)]
pub enum CommandType {
    /// Brute-force the encryption key from a separate binary, for an encrypted 'pck' file.
    Pck(CommandPck),
    /// Brute-force the encryption key from a binary, with embedded & encrypted 'pck' file.
    Embedded(CommandEmbedded),
}
