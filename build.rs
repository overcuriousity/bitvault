fn main() {
    // Resolve the real .git directory, handling both standard repos (.git dir)
    // and worktrees / submodules (.git file containing "gitdir: <path>").
    let git_dir = {
        let git_path = std::path::Path::new(".git");
        match std::fs::metadata(git_path) {
            Ok(m) if m.is_dir() => Some(git_path.to_path_buf()),
            Ok(m) if m.is_file() => std::fs::read_to_string(git_path)
                .ok()
                .and_then(|s| {
                    s.strip_prefix("gitdir: ")
                        .map(str::trim)
                        .filter(|p| !p.is_empty())
                        .map(std::path::PathBuf::from)
                }),
            _ => None,
        }
    };

    let commit = if git_dir.is_some() {
        std::process::Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_string())
    } else {
        "unknown".to_string()
    };
    println!("cargo:rustc-env=GIT_COMMIT_SHORT={commit}");

    // Emit rerun-if-changed only when the .git dir actually exists,
    // so source-tarball / non-git builds stay clean and incremental.
    if let Some(dir) = git_dir {
        let head = dir.join("HEAD");
        if head.exists() {
            println!("cargo:rerun-if-changed={}", head.display());
        }
        let packed = dir.join("packed-refs");
        if packed.exists() {
            println!("cargo:rerun-if-changed={}", packed.display());
        }
        if let Ok(contents) = std::fs::read_to_string(&head) {
            if let Some(reference) = contents.strip_prefix("ref: ") {
                let refpath = dir.join(reference.trim());
                if refpath.exists() {
                    println!("cargo:rerun-if-changed={}", refpath.display());
                }
            }
        }
    }
}
