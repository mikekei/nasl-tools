/// Parse every .nasl file and write root.to_string() back.
/// If the CST is truly lossless, `git diff` will show zero changes.
use std::path::Path;
use walkdir::WalkDir;

fn main() {
    let dir = match std::env::args().nth(1) {
        Some(d) => d,
        None => {
            eprintln!("Usage: rewrite <directory>");
            std::process::exit(1);
        }
    };

    let dir = Path::new(&dir);
    if !dir.exists() {
        eprintln!("Directory not found: {}", dir.display());
        std::process::exit(1);
    }

    let mut total = 0usize;
    let mut failed = 0usize;

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e: Result<walkdir::DirEntry, _>| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "nasl"))
    {
        let path = entry.path();
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("SKIP  {} (read error: {})", path.display(), e);
                continue;
            }
        };

        total += 1;
        let result = nasl_cst::parse(&source);
        let written = result.root.to_string();

        if written != source {
            eprintln!("FAIL  {}", path.display());
            failed += 1;
            continue;
        }

        if let Err(e) = std::fs::write(path, written.as_bytes()) {
            eprintln!("ERR   {} (write error: {})", path.display(), e);
            failed += 1;
            continue;
        }

        if total % 5000 == 0 {
            println!("  ... {} files processed", total);
        }
    }

    println!("\nDone: {} files processed, {} failed", total, failed);
    if failed > 0 {
        std::process::exit(1);
    }
}
