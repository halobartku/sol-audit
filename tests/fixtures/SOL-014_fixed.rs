// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::AccountInfo;

pub fn read_header(info: &AccountInfo) -> u64 {
    let bytes = info.data.borrow();
    let mut head = [0u8; 8];
    head.copy_from_slice(&bytes[0..8]);
    u64::from_le_bytes(head)
}
