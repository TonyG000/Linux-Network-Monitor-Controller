/*control.rs

FR10 : Traffic Control
  Block / unblock outbound traffic for a selected process using iptables.

How it works:
  Linux's iptables `owner` module can match packets by the UID of the
  process that sent them.  We look up the UID for a given PID (already
  available from process.rs) and insert an OUTPUT DROP rule scoped to
  that UID.  Removing the same rule unblocks the process.

Important limitations:
  • Blocking is per-UID, not per-PID.  If multiple processes share the
    same UID they will all be blocked together.  This is a kernel
    limitation — iptables has no stable per-PID match.
  • Blocking is only on outbound traffic. Inbound packets arrive before they are assigned to a process 
    and there is no reliable way to say "incoming packet X belongs to PID Y"
  • iptables requires root.  The programme must already be running as
    root (required anyway for libpcap capture).
  • All active rules are removed when TrafficController is dropped, so
    no orphaned DROP rules are left behind after the programme exits.*/


use std::collections::HashMap;
use std::process::Command;


// One entry per blocked process stored inside TrafficController.
#[derive(Debug, Clone)]
pub struct BlockedEntry {
    pub pid: u32,
    pub process_name: String,
    pub uid: u32,  // the UID the iptables rule was inserted for
}


pub struct TrafficController {
    // Keyed by PID so the GUI can look up whether a given process is blocked.
    // Value is the full entry so we have the UID when we need to remove the rule.
    blocked: HashMap<u32, BlockedEntry>,
}

impl TrafficController {
    pub fn new() -> Self {
        TrafficController {
            blocked: HashMap::new(),
        }
    }

    // Block outbound traffic for the process identified by pid
    // uid and process_name come from ProcessInfo (already resolved by process.rs).
    // Returns an error string if the iptables command fails.
    pub fn block(&mut self, pid: u32, uid: u32, process_name: &str) -> Result<(), String> {
        // Don't insert a duplicate rule if this PID is already blocked
        if self.blocked.contains_key(&pid) {
            return Ok(());
        }

        // Check whether any already-blocked entry uses the same UID.
        // If so, the iptables rule already exists just record the new PID
        let rule_already_exists = self.blocked.values().any(|e| e.uid == uid);

        if !rule_already_exists {
            // Insert: iptables -A OUTPUT -m owner --uid-owner <uid> -j DROP
            run_iptables(&[
                "-A", "OUTPUT",
                "-m", "owner",
                "--uid-owner", &uid.to_string(),
                "-j", "DROP",
            ])?;
        }

        self.blocked.insert(pid, BlockedEntry {
            pid,
            process_name: process_name.to_string(),
            uid,
        });

        Ok(())
    }

    // Unblock the process identified by pid
    // Removes the iptables rule only if no other blocked process shares the same UID.
    pub fn unblock(&mut self, pid: u32) -> Result<(), String> {
        // Remove the entry.. if it wasn't there, nothing to do
        let entry = match self.blocked.remove(&pid) {
            Some(e) => e,
            None    => return Ok(()),
        };

        // Check whether any remaining blocked entry still uses the same UID.
        // If so, leave the iptables rule in place for those other processes.
        let uid_still_needed = self.blocked.values().any(|e| e.uid == entry.uid);

        if !uid_still_needed {
            // Delete: iptables -D OUTPUT -m owner --uid-owner <uid> -j DROP
            run_iptables(&[
                "-D", "OUTPUT",
                "-m", "owner",
                "--uid-owner", &entry.uid.to_string(),
                "-j", "DROP",
            ])?;
        }

        Ok(())
    }

    // Returns true if the given PID is currently blocked.
    pub fn is_blocked(&self, pid: u32) -> bool {
        self.blocked.contains_key(&pid)
    }

    // Returns a snapshot of all currently blocked entries, sorted by PID.
    // Used by the GUI to render the blocked-process list.
    pub fn blocked_list(&self) -> Vec<&BlockedEntry> {
        let mut v: Vec<&BlockedEntry> = self.blocked.values().collect();
        v.sort_by_key(|e| e.pid);
        v
    }

    // Remove all active rules and clear the blocked map.
    // Called on exit to avoid leaving orphaned DROP rules in the kernel.
    pub fn unblock_all(&mut self) {
        // Collect the unique UIDs that have active rules
        let uids: Vec<u32> = {
            let mut seen = std::collections::HashSet::new();
            self.blocked.values()
                .filter(|e| seen.insert(e.uid))
                .map(|e| e.uid)
                .collect()
        };

        for uid in uids {
            if let Err(e) = run_iptables(&[
                "-D", "OUTPUT",
                "-m", "owner",
                "--uid-owner", &uid.to_string(),
                "-j", "DROP",
            ]) {
                eprintln!("control: failed to remove rule for uid {uid}: {e}");
            }
        }

        self.blocked.clear();
    }
}

// Clean up all rules automatically when TrafficController goes out of scope.
// This covers the case where the programme exits without an explicit shutdown.
impl Drop for TrafficController {
    fn drop(&mut self) {
        self.unblock_all();
    }
}


// Run iptables with the given arguments.
// Returns Ok(()) if the command exits with status 0, Err(message) otherwise.
fn run_iptables(args: &[&str]) -> Result<(), String> {
    let status = Command::new("iptables")
        .args(args)
        .status()
        .map_err(|e| format!("failed to execute iptables: {e}"))?;

    if status.success() {
        Ok(())
    } 
    else {
        Err(format!(
            "iptables {} exited with status {}",
            args.join(" "),
            status
        ))
    }
}