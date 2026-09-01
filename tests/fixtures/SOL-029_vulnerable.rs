// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

pub fn distribute(ctx: Context<Distribute>) -> Result<()> {
    for account in ctx.remaining_accounts.iter() {
        let mut share = account.try_borrow_mut_data()?;
        share[0] = 1;
    }
    Ok(())
}

#[derive(Accounts)]
pub struct Distribute<'info> {
    pub payer: Signer<'info>,
}
