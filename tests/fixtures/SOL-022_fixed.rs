// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use borsh::BorshDeserialize;
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

#[derive(BorshDeserialize, PartialEq)]
pub enum AccountTag {
    Uninitialized,
    Admin,
    User,
}

#[derive(BorshDeserialize)]
pub struct AdminConfig {
    pub discriminant: AccountTag,
    pub admin: Pubkey,
    pub fee_bps: u16,
}

pub fn set_fee(accounts: &[AccountInfo], fee_bps: u16) -> ProgramResult {
    let config_info = &accounts[0];
    let mut config = AdminConfig::try_from_slice(&config_info.data.borrow())?;
    if config.discriminant != AccountTag::Admin {
        return Err(ProgramError::InvalidAccountData);
    }
    config.fee_bps = fee_bps;
    Ok(())
}
