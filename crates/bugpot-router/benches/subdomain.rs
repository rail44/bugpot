//! Microbenchmarks for [`bugpot_router::subdomain_of`].
//!
//! Called for every HTTP request that reaches the router so any
//! regression compounds with traffic. The function is small (string
//! splits on `:` and `.`) and dominated by branch prediction —
//! tracked here mostly to lock in the absence of allocations.

use bugpot_router::subdomain_of;
use divan::Bencher;

fn main() {
    divan::main();
}

#[divan::bench(args = [
    "alpha.localhost",
    "beta.bugpot.example:8080",
    "myapp.bugpot.example.com",
    "very-long-subdomain.bugpot.somewhere.example.org:443",
])]
fn typical(bencher: Bencher, host: &'static str) {
    bencher.bench(|| subdomain_of(divan::black_box(host)));
}

#[divan::bench(args = [
    "",
    "[::1]:8080",
    "127.0.0.1:8080",
])]
fn edge_cases(bencher: Bencher, host: &'static str) {
    bencher.bench(|| subdomain_of(divan::black_box(host)));
}
