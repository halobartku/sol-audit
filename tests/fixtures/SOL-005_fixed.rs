// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

pub fn draw(ctx: Context<Draw>, entrants: Vec<Pubkey>) -> Result<()> {
    let index = ctx.accounts.vrf_result.value as usize;
    let picked = entrants[index % entrants.len()];
    msg!("picked {}", picked);
    Ok(())
}

#[derive(Accounts)]
pub struct Draw<'info> {
    pub vrf_result: Account<'info, VrfResult>,
    pub caller: Signer<'info>,
}

#[account]
pub struct VrfResult {
    pub value: u64,
}
