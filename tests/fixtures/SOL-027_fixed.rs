// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::load_instruction_at_checked;

pub fn guarded_mint(ctx: Context<GuardedMint>) -> Result<()> {
    let previous = load_instruction_at_checked(0, &ctx.accounts.instructions)?;
    require_keys_eq!(previous.program_id, crate::ID, MintError::ForeignNeighbour);
    if previous.data[0] != 9 {
        return err!(MintError::WrongNeighbour);
    }
    Ok(())
}

#[derive(Accounts)]
pub struct GuardedMint<'info> {
    /// CHECK: the instructions sysvar
    pub instructions: UncheckedAccount<'info>,
    pub minter: Signer<'info>,
}

#[error_code]
pub enum MintError {
    WrongNeighbour,
    ForeignNeighbour,
}
