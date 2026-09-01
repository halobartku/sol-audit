// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

pub fn accrue(state: &mut Ledger, interest: u64) -> Result<()> {
    state.principal += interest;
    Ok(())
}

pub struct Ledger {
    pub principal: u64,
}
