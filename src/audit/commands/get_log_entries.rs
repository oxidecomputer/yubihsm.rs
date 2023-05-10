//! Get audit logs from the `YubiHSM 2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Log_Entries.html>

use crate::{
    command::{self, Command},
    object,
    response::{self, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug};

/// Request parameters for `command::get_log_entries`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetLogEntriesCommand {}

impl Command for GetLogEntriesCommand {
    type ResponseType = LogEntries;
}

/// Response from `command::get_log_entries`
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LogEntries {
    /// Number of boot events which weren't logged (if buffer is full and audit enforce is set)
    pub unlogged_boot_events: u16,

    /// Number of unlogged authentication events (if buffer is full and audit enforce is set)
    pub unlogged_auth_events: u16,

    /// Number of entries in the response
    pub num_entries: u8,

    /// Entries in the log
    pub entries: Vec<LogEntry>,
}

impl Response for LogEntries {
    const COMMAND_CODE: command::Code = command::Code::GetLogEntries;
}

/// Entry in the log response
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct LogEntry {
    /// Entry number
    pub item: u16,

    /// Command type
    pub cmd: command::Code,

    /// Command length
    pub length: u16,

    /// Session key ID
    pub session_key: object::Id,

    /// Target key ID
    pub target_key: object::Id,

    /// Second key affected
    pub second_key: object::Id,

    /// Result of the operation
    pub result: response::Code,

    /// Tick count of the HSM's internal clock
    pub tick: u32,

    /// 16-byte truncated SHA-256 digest of this log entry and the digest of the previous entry
    pub digest: LogDigest,
}

/// Size of a truncated digest in the log
pub const LOG_DIGEST_SIZE: usize = 16;

/// Truncated SHA-256 digest of a log entry and the previous log digest
#[derive(Serialize, Deserialize, PartialEq)]
pub struct LogDigest(pub [u8; LOG_DIGEST_SIZE]);

impl AsRef<[u8]> for LogDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Debug for LogDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogDigest(")?;
        for (i, byte) in self.0.iter().enumerate() {
            write!(f, "{:02x}", byte)?;
            write!(f, "{}", if i == LOG_DIGEST_SIZE - 1 { ")" } else { ":" })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::serialization::deserialize;

    const DATA: [u8; 133] = [
        0, 0, 0, 0, 4,
        0, 1, 255,
        255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 244, 100, 88,
        173, 51, 247, 120, 239, 19, 99, 194,
        163, 154, 37, 95, 160,
        0, 2, 0,
        0, 0, 255, 255, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 226, 191, 66,
        113, 6, 162, 38, 178, 50, 169, 103,
        216, 55, 101, 4, 30,
        0, 3, 3,
        0, 10, 255, 255, 0, 1, 255, 255,
        131, 0, 0, 5, 85, 82, 98, 183,
        36, 231, 60, 175, 60, 53, 195, 246,
        45, 231, 164, 42, 219,
        0, 4, 4,
        0, 17, 255, 255, 0, 1, 255, 255,
        132, 0, 0, 5, 86, 229, 163, 252,
        211, 228, 178, 7, 135, 149, 191, 55,
        231, 134, 255, 142, 40,
    ];

    #[test]
    fn foo() {
        let baz: [u8; 5] = [ 0, 0, 0, 0, 4, ];

        let bar1: LogEntries = deserialize(&DATA).expect("fml1");
        println!("bar1: {:#?}", bar1);

        let bar2: LogEntries = deserialize(&baz).expect("fml2");
        println!("bar2: {:#?}", bar1);

        // because why would you implement PartialEq?
        assert_ne!(bar1, bar2);
    }

    #[test]
    fn log_entry_initial() {
        let buf: [u8; 32] = [
            0, 1, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255,
            244, 100, 88, 173, 51, 247, 120, 239,
            19, 99, 194, 163, 154, 37, 95, 160,
        ];

        let entry: LogEntry = deserialize(&buf).expect("fml");
        println!("entry: {:#?}", entry);
    }

    #[test]
    fn log_entry_boot() {
        let buf: [u8; 32] = [
            0, 2, 0, 0, 0, 255, 255, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            226, 191, 66, 113, 6, 162, 38, 178,
            50, 169, 103, 216, 55, 101, 4, 30,
        ];

        let entry: LogEntry = deserialize(&buf).expect("fml");
        println!("entry: {:#?}", entry);
    }
 }
