#[macro_use]
extern crate lazy_static;

use parking_lot::RwLock;
use std::sync::Arc;

mod config;
mod core;
mod formatter;

lazy_static! {
    static ref CONFIG: Arc<RwLock<config::Config>> = Arc::new(RwLock::new(config::Config::new()));
}

fn main() {
    let handle = std::thread::spawn(|| {
        core::core_thread();
    });

    let _ = handle.join();
}
