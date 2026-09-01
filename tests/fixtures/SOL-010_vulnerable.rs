// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program::invoke;
use solana_program::instruction::Instruction;

pub fn relay(accounts: &[AccountInfo], data: Vec<u8>) -> ProgramResult {
    let iter = &mut accounts.iter();
    let target = next_account_info(iter)?;
    let ix = Instruction { program_id: *target.key, accounts: vec![], data };
    invoke(&ix, accounts)?;
    Ok(())
}
