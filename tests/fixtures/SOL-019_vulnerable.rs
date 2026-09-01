// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

pub fn tick(ctx: Context<Tick>) -> Result<()> {
    let bytes = ctx.accounts.clock.try_borrow_data()?;
    msg!("slot byte {}", bytes[0]);
    Ok(())
}

#[derive(Accounts)]
pub struct Tick<'info> {
    /// CHECK: never compared with the real clock sysvar address
    pub clock: UncheckedAccount<'info>,
    pub caller: Signer<'info>,
}
