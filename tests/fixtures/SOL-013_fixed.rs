// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;
use anchor_spl::token;

pub fn issue(ctx: Context<Issue>, qty: u64) -> Result<()> {
    let expected = ctx.accounts.mint.mint_authority.unwrap();
    require_keys_eq!(expected, ctx.accounts.caller.key(), IssueError::NotMintAuthority);
    let cpi = ctx.accounts.mint_context();
    token::mint_to(cpi, qty)?;
    Ok(())
}

#[derive(Accounts)]
pub struct Issue<'info> {
    pub mint: Account<'info, anchor_spl::token::Mint>,
    pub caller: Signer<'info>,
}

#[error_code]
pub enum IssueError {
    NotMintAuthority,
}
