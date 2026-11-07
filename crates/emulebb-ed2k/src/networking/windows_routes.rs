//! Read Windows IPv4 default-route ownership without assuming adapters have gateways.

use std::{collections::HashSet, ptr::NonNull};

use anyhow::{Context, Result};
use windows_sys::Win32::{
    NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    },
    Networking::WinSock::AF_INET,
};

struct RouteTable(NonNull<MIB_IPFORWARD_TABLE2>);

impl Drop for RouteTable {
    fn drop(&mut self) {
        // SAFETY: this is the uniquely owned allocation returned by GetIpForwardTable2;
        // no borrowed rows outlive the owner, and Windows requires FreeMibTable.
        unsafe { FreeMibTable(self.0.as_ptr().cast()) };
    }
}

pub(super) fn default_route_indices() -> Result<HashSet<u32>> {
    let mut table = std::ptr::null_mut();
    // SAFETY: table is a writable out-pointer. AF_INET restricts the allocated
    // snapshot to IPv4; on success its lifetime is owned below and never mutated.
    let status = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("GetIpForwardTable2 failed to read Windows IPv4 routes");
    }
    let table =
        RouteTable(NonNull::new(table).context("Windows returned a null IPv4 route table")?);
    // SAFETY: the successful API call provides NumEntries initialized, aligned
    // rows in its variable-length allocation. addr_of avoids borrowing the
    // placeholder one-element array when the snapshot is empty. The owner
    // retains the allocation throughout this read and the returned set owns its data.
    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table.0.as_ptr()).Table).cast::<MIB_IPFORWARD_ROW2>(),
            (*table.0.as_ptr()).NumEntries as usize,
        )
    };
    Ok(indices_from_rows(rows))
}

fn indices_from_rows(rows: &[MIB_IPFORWARD_ROW2]) -> HashSet<u32> {
    rows.iter()
        .filter(|row| {
            // SAFETY: si_family is the common discriminant of SOCKADDR_INET.
            let family = unsafe { row.DestinationPrefix.Prefix.si_family };
            // WHY: tunnel default routes can be on-link with no adapter gateway.
            // Use route ownership, retaining all candidates so ambiguity fails closed.
            family == AF_INET
                && row.DestinationPrefix.PrefixLength == 0
                && row.ValidLifetime != 0
                && !row.Loopback
                && row.InterfaceIndex != 0
        })
        .map(|row| row.InterfaceIndex)
        .collect()
}

#[cfg(test)]
mod tests;
