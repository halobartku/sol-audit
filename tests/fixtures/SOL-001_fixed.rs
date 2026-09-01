// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use anchor_lang::prelude::*;
declare_id!("Fix1ure11111111111111111111111111111111111");

#[program]
pub mod fee_config {
    use super::*;
    pub fn set_fee(ctx: Context<SetFee>, fee: u64) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.fee = fee;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetFee<'info> {
    #[account(mut)]
    pub config: Account<'info, FeeConfig>,
    pub authority: Signer<'info>,
}

#[account]
pub struct FeeConfig {
    pub fee: u64,
}
