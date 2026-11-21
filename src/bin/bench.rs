//! `cargo run --release --bin bench [rounds] [--json]`: per-check latency (µs).
use mcpgw::{bench, corpus};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rounds = args.iter().find_map(|s| s.parse().ok()).unwrap_or(3);
    let r = bench::run(&corpus::attacks(), &corpus::benign(), rounds);
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string(&r).unwrap());
        return;
    }
    println!("{:<16} {:>8} {:>9} {:>9} {:>9}", "check", "calls", "p50 µs", "p99 µs", "max µs");
    for (k, s) in &r {
        println!("{k:<16} {:>8} {:>9.2} {:>9.2} {:>9.2}", s.calls, s.p50_us, s.p99_us, s.max_us);
    }
}
