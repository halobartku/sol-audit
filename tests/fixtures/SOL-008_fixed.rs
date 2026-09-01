// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Open<'info> {
    #[account(init, payer = user, space = 8 + 32 + 8)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub size: u64,
}
