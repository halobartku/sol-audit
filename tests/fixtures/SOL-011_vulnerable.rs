// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::instruction::Instruction;
use solana_program::program::invoke_signed;

pub struct VaultAuthority {
    pub seeds: Vec<Vec<u8>>,
    pub bump: u8,
}

pub fn withdraw(accounts: &[AccountInfo], ix: Instruction, auth: VaultAuthority)
    -> ProgramResult {
    let signer: &[&[u8]] = &[b"vault", &[auth.bump]];
    invoke_signed(&ix, accounts, &[signer])?;
    Ok(())
}
