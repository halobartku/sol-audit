// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::program::invoke;
use solana_program::system_instruction;

pub fn open(accounts: &[AccountInfo], payload: &[u8], lamports: u64) -> ProgramResult {
    let space = payload.len() as u64;
    let ix = system_instruction::create_account(
        accounts[0].key, accounts[1].key, lamports, space, accounts[2].key);
    invoke(&ix, accounts)?;
    Ok(())
}
