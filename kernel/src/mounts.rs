//! The runtime mount registry: what is mounted, from where, and how.
//!
//! Each record pairs a mount point with the volume identity, filesystem
//! profile, and access mode it was activated under, so the diagnostics
//! surfaces and `/sys` projections can report the machine's storage shape
//! without re-reading any volume.
//!
//! ADR 0035 Phase E wants mount policy out of the kernel: this registry is the
//! kernel-resident record of a decision a user-space volume manager should be
//! making. Reading that record back from the server is part of the
//! `kernel/src/client.rs` ADR 0035 names.

use alloc::string::String;
use alloc::vec::Vec;
use troe_abi::volume_control;
use troe_dispatch::ReplyStatus;
use troe_fmt_bmnt::{AccessMode, ActivationMode, BootMountManifest, FilesystemProfile};
use troe_namespace::Namespace;
use troe_volume::PreparedMount;

pub(crate) struct RuntimeMountRecord {
    name: String,
    filesystem: volume_control::Filesystem,
    access: volume_control::Access,
    activation: volume_control::Activation,
    state: volume_control::State,
    prepared: Option<PreparedMount>,
}

pub(crate) struct RuntimeMountRegistry {
    entries: Vec<RuntimeMountRecord>,
}

impl RuntimeMountRegistry {
    pub(crate) const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn configure(
        &mut self,
        manifest: &BootMountManifest,
        mut prepared: Vec<PreparedMount>,
        namespace: &mut Namespace,
    ) -> Result<(), ()> {
        if !self.entries.is_empty() {
            return Err(());
        }
        self.entries
            .try_reserve_exact(manifest.entries().len())
            .map_err(|_| ())?;
        for entry in manifest.entries() {
            let path = alloc::format!("/vol/{}", entry.name());
            let plan = prepared
                .iter()
                .position(|plan| plan.path() == path)
                .map(|index| prepared.remove(index));
            if plan
                .as_ref()
                .is_some_and(|plan| plan.activation() != entry.activation())
            {
                return Err(());
            }
            let (state, prepared) = match (entry.activation(), plan) {
                (ActivationMode::Auto, Some(plan)) => {
                    plan.attach(namespace).map_err(|_| ())?;
                    (volume_control::State::Mounted, None)
                }
                (ActivationMode::Manual, Some(plan)) => (volume_control::State::Ready, Some(plan)),
                (_, None) => (volume_control::State::Unavailable, None),
            };
            let mut name = String::new();
            name.try_reserve_exact(entry.name().len()).map_err(|_| ())?;
            name.push_str(entry.name());
            self.entries.push(RuntimeMountRecord {
                name,
                filesystem: match entry.filesystem() {
                    FilesystemProfile::Fat32 => volume_control::Filesystem::Fat32,
                    FilesystemProfile::Ext4V1 => volume_control::Filesystem::Ext4V1,
                },
                access: match entry.access() {
                    AccessMode::ReadOnly => volume_control::Access::ReadOnly,
                    AccessMode::ReadWrite => volume_control::Access::ReadWrite,
                },
                activation: match entry.activation() {
                    ActivationMode::Auto => volume_control::Activation::Auto,
                    ActivationMode::Manual => volume_control::Activation::Manual,
                },
                state,
                prepared,
            });
        }
        if prepared.is_empty() { Ok(()) } else { Err(()) }
    }

    pub(crate) fn encode_list(&self, output: &mut [u8]) -> Result<usize, ()> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(self.entries.len())
            .map_err(|_| ())?;
        for entry in &self.entries {
            entries.push(volume_control::VolumeInfo {
                name: &entry.name,
                filesystem: entry.filesystem,
                access: entry.access,
                activation: entry.activation,
                state: entry.state,
            });
        }
        volume_control::encode_list(&entries, output).map_err(|_| ())
    }

    pub(crate) fn activate(
        &mut self,
        name: &str,
        namespace: &mut Namespace,
    ) -> Result<(), ReplyStatus> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.name == name)
            .ok_or(ReplyStatus::NotFound)?;
        match entry.state {
            volume_control::State::Mounted => Ok(()),
            volume_control::State::Unavailable => Err(ReplyStatus::NotFound),
            volume_control::State::Failed => Err(ReplyStatus::Failure),
            volume_control::State::Ready => {
                if entry.activation != volume_control::Activation::Manual {
                    return Err(ReplyStatus::InvalidRequest);
                }
                let plan = entry.prepared.take().ok_or(ReplyStatus::Corrupt)?;
                if let Ok(()) = plan.attach(namespace) {
                    entry.state = volume_control::State::Mounted;
                    let _updated = mark_storage_role_mounted(namespace, name);
                    Ok(())
                } else {
                    entry.state = volume_control::State::Failed;
                    Err(ReplyStatus::Failure)
                }
            }
        }
    }
}

pub(crate) fn mark_storage_role_mounted(namespace: &mut Namespace, name: &str) -> Result<(), ()> {
    let current = namespace.read_file("/", "/sys/storage").map_err(|_| ())?;
    let current = core::str::from_utf8(&current).map_err(|_| ())?;
    let prefix = alloc::format!("role {name} ");
    let marker = " state=ready volume=";
    let replacement = " state=mounted volume=";
    let mut updated = String::new();
    updated
        .try_reserve_exact(
            current
                .len()
                .saturating_add(replacement.len() - marker.len()),
        )
        .map_err(|_| ())?;
    let mut changed = false;
    for line in current.split_inclusive('\n') {
        if line.starts_with(&prefix) {
            let offset = line.find(marker).ok_or(())?;
            updated.push_str(&line[..offset]);
            updated.push_str(replacement);
            updated.push_str(&line[offset + marker.len()..]);
            changed = true;
        } else {
            updated.push_str(line);
        }
    }
    if !changed {
        return Err(());
    }
    namespace
        .set_system_file("/sys/storage", updated.as_bytes())
        .map_err(|_| ())
}
