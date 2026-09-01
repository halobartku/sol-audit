// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::program::invoke;
use solana_program::instruction::Instruction;

pub fn forward(accounts: &[AccountInfo], ix: Instruction) -> ProgramResult {
    invoke(&ix, accounts)?;
    Ok(())
}
