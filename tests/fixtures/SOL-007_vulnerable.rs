// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::{next_account_info, AccountInfo};
use solana_program::entrypoint::ProgramResult;

pub fn set_admin(accounts: &[AccountInfo]) -> ProgramResult {
    let iter = &mut accounts.iter();
    let admin_info = next_account_info(iter)?;
    let config_info = next_account_info(iter)?;
    config_info.data.borrow_mut()[0..32].copy_from_slice(admin_info.key.as_ref());
    Ok(())
}
