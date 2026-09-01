// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;

pub fn read(ctx: Context<Read>) -> Result<()> {
    let raw = ctx.accounts.state.to_account_info();
    let bytes = raw.try_borrow_data()?;
    msg!("{}", bytes[0]);
    Ok(())
}

#[derive(Accounts)]
pub struct Read<'info> {
    pub state: Account<'info, State>,
}

#[account]
pub struct State {
    pub value: u64,
}
