// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::program_error::ProgramError;
use solana_program::pubkey::Pubkey;

pub fn claim(accounts: &[AccountInfo], program_id: &Pubkey, seed_bump: u8) -> ProgramResult {
    let expected = Pubkey::create_program_address(
        &[b"reward", accounts[0].key.as_ref(), &[seed_bump]], program_id)
        .map_err(|_| ProgramError::InvalidSeeds)?;
    if expected != *accounts[1].key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}
