use radix_engine::ledger::InMemorySubstateStore;

pub struct Config {
    pub updated: bool,
    pub ledger: InMemorySubstateStore,
}

impl Config {
    pub fn new() -> Config {
        Config {
            updated: false,
            ledger: InMemorySubstateStore::with_bootstrap(),
        }
    }

    pub fn increment_epoch(&mut self) {}

    pub fn load(&mut self) -> &mut InMemorySubstateStore {
        &mut self.ledger
    }

    pub fn load_immutable(&self) -> &InMemorySubstateStore {
        &self.ledger
    }
}
