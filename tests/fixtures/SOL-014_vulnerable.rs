// sol-audit fixture. Hand-written for this repository from a published description of the
// vulnerability class. Not taken from any benchmark corpus. Never compiled: there is no
// cargo on the machine this was written on, so treat it as text the scanner reads.
use solana_program::account_info::AccountInfo;

pub fn read_header(info: &AccountInfo) -> u64 {
    let bytes = info.data.borrow();
    unsafe { *(bytes.as_ptr() as *const u64) }
}
