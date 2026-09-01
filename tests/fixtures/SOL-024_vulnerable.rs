// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
pub fn share_of(total_deposits: u64, total_shares: u64, user_shares: u64) -> u64 {
    (total_deposits / total_shares) * user_shares
}
