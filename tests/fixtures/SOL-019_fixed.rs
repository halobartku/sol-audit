// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

pub fn tick(ctx: Context<Tick>) -> Result<()> {
    msg!("slot {}", ctx.accounts.clock.slot);
    Ok(())
}

#[derive(Accounts)]
pub struct Tick<'info> {
    pub clock: Sysvar<'info, Clock>,
    pub caller: Signer<'info>,
}
