// Embeds the commit the crate was built from: an ordinary build script, and one that starts a
// process on every `cargo build` -- which is what makes build scripts worth reporting.
use std::process::Command;

fn main() {
    let output = Command::new("git").args(["rev-parse", "HEAD"]).output();
    if let Ok(output) = output {
        let commit = String::from_utf8_lossy(&output.stdout);
        println!("cargo:rustc-env=BUILD_COMMIT={}", commit.trim());
    }
}
