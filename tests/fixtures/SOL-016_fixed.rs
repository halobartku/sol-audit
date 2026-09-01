// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut, seeds = [b"ticket", user.key().as_ref()], bump = ticket.bump)]
    pub ticket: Account<'info, Ticket>,
    pub user: Signer<'info>,
}

#[account]
pub struct Ticket {
    pub bump: u8,
}
