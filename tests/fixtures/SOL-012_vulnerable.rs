// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;
use anchor_spl::token;

pub fn payout(ctx: Context<Payout>, amount: u64) -> Result<()> {
    let cpi = ctx.accounts.transfer_context();
    token::transfer(cpi, amount)?;
    Ok(())
}

#[derive(Accounts)]
pub struct Payout<'info> {
    pub authority: Signer<'info>,
}
