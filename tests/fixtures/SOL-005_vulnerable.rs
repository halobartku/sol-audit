// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

pub fn draw(ctx: Context<Draw>, entrants: Vec<Pubkey>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let winner = entrants[(now as usize) % entrants.len()];
    msg!("winner {}", winner);
    Ok(())
}

#[derive(Accounts)]
pub struct Draw<'info> {
    pub caller: Signer<'info>,
}
