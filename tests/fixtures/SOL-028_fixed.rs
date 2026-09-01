// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct Config {
    pub is_initialized: bool,
    pub admin: Pubkey,
}

pub fn process_initialize(accounts: &[AccountInfo], admin: Pubkey) -> ProgramResult {
    let config_info = &accounts[0];
    let existing = Config::try_from_slice(&config_info.data.borrow())?;
    if existing.is_initialized {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    let config = Config { is_initialized: true, admin };
    config.serialize(&mut *config_info.data.borrow_mut())?;
    Ok(())
}
