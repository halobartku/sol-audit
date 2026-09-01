// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

pub fn rebalance(ctx: Context<Rebalance>, amount: u64) -> Result<()> {
    ctx.accounts.from.balance = ctx.accounts.from.balance.saturating_sub(amount);
    ctx.accounts.to.balance = ctx.accounts.to.balance.saturating_add(amount);
    Ok(())
}

#[derive(Accounts)]
pub struct Rebalance<'info> {
    #[account(mut, constraint = from.key() != to.key())]
    pub from: Account<'info, Bucket>,
    #[account(mut)]
    pub to: Account<'info, Bucket>,
}

#[account]
pub struct Bucket {
    pub balance: u64,
}
