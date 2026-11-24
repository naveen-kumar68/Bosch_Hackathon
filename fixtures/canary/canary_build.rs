// GUARDIAN TEST FIXTURE - harmless. Used only to check that Guardian's capability rules fire.
// It never contacts any real host and never reads real secrets.
use std::net::TcpStream;

fn main() {
    let _ = TcpStream::connect("127.0.0.1:9");            // looks like "network access"
    let _vars: Vec<(String, String)> = std::env::vars().collect(); // looks like "reads environment"
    println!("cargo:rerun-if-changed=build.rs");
}