// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;
use solana_program::program_memory::sol_memset;

pub fn close(ctx: Context<CloseRecord>) -> Result<()> {
    let record = ctx.accounts.record.to_account_info();
    let destination = ctx.accounts.destination.to_account_info();
    **destination.lamports.borrow_mut() += record.lamports();
    **record.lamports.borrow_mut() = 0;
    let mut data = record.try_borrow_mut_data()?;
    let len = data.len();
    sol_memset(&mut data, 0, len);
    Ok(())
}

#[derive(Accounts)]
pub struct CloseRecord<'info> {
    #[account(mut)]
    pub record: Account<'info, Record>,
    /// CHECK: receives the rent
    #[account(mut)]
    pub destination: AccountInfo<'info>,
}

#[account]
pub struct Record {
    pub value: u64,
}
