// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(amount: u64)]
pub struct Claim<'info> {
    #[account(mut, seeds = [b"claim", user.key().as_ref()], bump = claim.bump)]
    pub claim: Account<'info, ClaimState>,
    pub user: Signer<'info>,
}

#[account]
pub struct ClaimState {
    pub bump: u8,
    pub amount: u64,
}
