// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::AccountInfo;
use solana_program::entrypoint::ProgramResult;
use solana_program::program::invoke_signed;
use solana_program::instruction::Instruction;
use solana_program::pubkey::Pubkey;

pub fn withdraw(accounts: &[AccountInfo], ix: Instruction, program_id: &Pubkey) -> ProgramResult {
    let (_pda, canonical) = Pubkey::find_program_address(&[b"vault"], program_id);
    let seeds: &[&[u8]] = &[b"vault", &[canonical]];
    invoke_signed(&ix, accounts, &[seeds])?;
    Ok(())
}
