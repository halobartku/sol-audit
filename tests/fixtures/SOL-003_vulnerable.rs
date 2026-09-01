// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;
declare_id!("Fix3ure11111111111111111111111111111111111");

#[derive(Accounts)]
pub struct OpenAccount<'info> {
    #[account(init_if_needed, payer = user, space = 8 + 40)]
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
