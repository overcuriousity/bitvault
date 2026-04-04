fn main() {
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_COMMIT_SHORT={commit}");

    // Rebuild when the current commit changes.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    // Also watch the specific ref file that HEAD points to (e.g. refs/heads/master).
    if let Ok(head) = std::fs::read_to_string(".git/HEAD") {
        if let Some(reference) = head.strip_prefix("ref: ") {
            let reference = reference.trim();
            println!("cargo:rerun-if-changed=.git/{reference}");
        }
    }
}
