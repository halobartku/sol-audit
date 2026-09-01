// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::program_pack::Pack;
use spl_token::state::Account as TokenAccount;

pub fn require_balance(accounts: &[AccountInfo], minimum: u64) -> ProgramResult {
    let iter = &mut accounts.iter();
    let token_info = next_account_info(iter)?;
    if token_info.owner != &spl_token::ID {
        return Err(ProgramError::IllegalOwner);
    }
    let token = TokenAccount::unpack(&token_info.data.borrow())?;
    if token.amount < minimum {
        return Err(ProgramError::InsufficientFunds);
    }
    Ok(())
}
