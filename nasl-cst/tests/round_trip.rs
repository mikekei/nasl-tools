/// Integration test: parse every .nasl file under the directory specified by
/// the `NASL_PLUGIN_DIR` environment variable and verify that
/// `root.to_string() == original_source`.
/// This is the core correctness guarantee of the lossless CST.
///
/// Run with:
///   NASL_PLUGIN_DIR=/path/to/plugins cargo test --release -- --nocapture
use std::path::Path;
use walkdir::WalkDir;

#[test]
fn round_trip_all_nasl_files() {
    let nvt_dir = match std::env::var("NASL_PLUGIN_DIR") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => {
            eprintln!("NASL_PLUGIN_DIR not set, skipping round-trip test");
            return;
        }
    };

    if !nvt_dir.exists() {
        eprintln!("NASL_PLUGIN_DIR {:?} not found, skipping", nvt_dir);
        return;
    }

    let mut total = 0usize;
    let mut failed = 0usize;
    let mut fail_examples: Vec<String> = Vec::new();

    for entry in WalkDir::new(nvt_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |x| x == "nasl"))
    {
        let path = entry.path();
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => continue, // skip unreadable files
        };

        total += 1;
        let result = nasl_cst::parse(&source);
        if !result.round_trips(&source) {
            failed += 1;
            if fail_examples.len() < 5 {
                fail_examples.push(format!("{}", path.display()));
            }
        }
    }

    println!("Round-trip: {}/{} files passed", total - failed, total);

    if failed > 0 {
        panic!(
            "{} / {} files failed round-trip. First failures:\n{}",
            failed,
            total,
            fail_examples.join("\n")
        );
    }
}
