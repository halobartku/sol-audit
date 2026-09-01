// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;
use anchor_spl::token;

pub fn payout(ctx: Context<Payout>, requested: u64) -> Result<()> {
    require!(requested <= ctx.accounts.vault.cap, PayoutError::AboveCap);
    let amount = requested.checked_sub(ctx.accounts.vault.fee).ok_or(PayoutError::Math)?;
    let cpi = ctx.accounts.transfer_context();
    token::transfer(cpi, amount)?;
    Ok(())
}

#[derive(Accounts)]
pub struct Payout<'info> {
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Vault {
    pub cap: u64,
    pub fee: u64,
}

#[error_code]
pub enum PayoutError {
    AboveCap,
    Math,
}
