// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;
use anchor_spl::token;

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    token::transfer(ctx.accounts.transfer_context(), amount)?;
    let remaining = ctx.accounts.pool.total_liquidity;
    msg!("pool now holds {}", remaining);
    Ok(())
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    pub depositor: Signer<'info>,
}

#[account]
pub struct Pool {
    pub total_liquidity: u64,
}
