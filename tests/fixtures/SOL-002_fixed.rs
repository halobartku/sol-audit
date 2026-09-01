// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;
declare_id!("Fix2ure11111111111111111111111111111111111");

#[program]
pub mod metadata_reader {
    use super::*;
    pub fn read_flag(ctx: Context<ReadFlag>) -> Result<()> {
        require_keys_eq!(*ctx.accounts.metadata.owner, crate::ID, ReadError::ForeignAccount);
        let bytes = ctx.accounts.metadata.try_borrow_data()?;
        msg!("flag {}", bytes[0]);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ReadFlag<'info> {
    /// CHECK: owner is compared against this program above
    pub metadata: UncheckedAccount<'info>,
    pub caller: Signer<'info>,
}

#[error_code]
pub enum ReadError {
    ForeignAccount,
}
