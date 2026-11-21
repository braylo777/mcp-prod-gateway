//! Write `corpus/attacks.jsonl` and `corpus/benign.jsonl` (deterministic) and print the eval.
//! `--check` fails if the committed files differ from the generator output.

use mcpgw::{corpus, eval};

fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let a = corpus::attacks();
    let b = corpus::benign();
    let (ja, jb) = (corpus::to_jsonl(&a), corpus::to_jsonl(&b));
    if std::env::args().any(|x| x == "--check") {
        let same = std::fs::read_to_string(root.join("attacks.jsonl")).ok() == Some(ja)
            && std::fs::read_to_string(root.join("benign.jsonl")).ok() == Some(jb);
        if !same {
            eprintln!("corpus out of date: run `cargo run --bin gen-corpus`");
            std::process::exit(1);
        }
    } else {
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("attacks.jsonl"), ja).unwrap();
        std::fs::write(root.join("benign.jsonl"), jb).unwrap();
    }
    let r = eval::run(&a, &b);
    println!("{}", serde_json::to_string_pretty(&r).unwrap());
    println!("caught {}/{} ({:.3}) · fp manifests {}/{} ({:.4})", r.caught, r.attacks, r.recall(), r.fp_manifests, r.manifests, r.fp_rate());
}
