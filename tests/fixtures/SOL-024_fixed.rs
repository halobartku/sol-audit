// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
pub fn share_of(total_deposits: u128, total_shares: u128, user_shares: u128) -> Option<u128> {
    total_deposits.checked_mul(user_shares)?.checked_div(total_shares)
}
