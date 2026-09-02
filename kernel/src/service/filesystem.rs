//! Filesystem, filesystem-mutation, and volume-control services.
//!
//! These endpoints let an application read, write, and rename through the
//! kernel's namespace, and mount or unmount a volume through the kernel's
//! activation policy.
//!
//! ADR 0035 Phase D and E want both authorities out of the kernel: the
//! mutation service performs provider writes inside the privileged address
//! space, and the volume-control service is a direct handle onto the storage
//! activation policy Phase E removes. The endpoints move to the VFS/storage
//! server; the kernel's own calls into it become part of the
//! `kernel/src/client.rs` ADR 0035 names.

use crate::handles::{OwnedNamespace, SharedRuntimeMounts};
use alloc::string::String;
use alloc::vec::Vec;
use troe_abi::{filesystem, filesystem_mutation, volume_control};
use troe_dispatch::{ReplyStatus, Request, Service, ServiceReply};
use troe_fs_api::{FILE_IO_BUFFER_BYTES, FsError, NodeKind};
use troe_shell::SharedNamespace;

pub(crate) struct ApplicationFilesystemService {
    namespace: SharedNamespace,
    cwd: String,
    files: Vec<ApplicationFileSlot>,
}

pub(crate) struct ApplicationFilesystemMutationService {
    namespace: SharedNamespace,
    cwd: String,
    next_token: Option<u32>,
    pending: Option<PendingFileReplacement>,
}

pub(crate) struct ApplicationVolumeControlService {
    /// Activating a manifest volume attaches a provider, which is
    /// composition authority rather than client access.
    pub(crate) namespace: OwnedNamespace,
    pub(crate) mounts: SharedRuntimeMounts,
}

pub(crate) struct PendingFileReplacement {
    token: u32,
    path: String,
    start_offset: u64,
    offset: u64,
    bytes: Vec<u8>,
    chunk_bytes: usize,
}

pub(crate) struct ApplicationFileSlot {
    generation: u32,
    retired: bool,
    path: Option<String>,
    byte_count: u64,
}

impl ApplicationFilesystemService {
    pub(crate) fn new(namespace: SharedNamespace, cwd: &str) -> Result<Self, ()> {
        let mut owned_cwd = String::new();
        owned_cwd.try_reserve_exact(cwd.len()).map_err(|_| ())?;
        owned_cwd.push_str(cwd);
        let mut files = Vec::new();
        files.try_reserve_exact(64).map_err(|_| ())?;
        Ok(Self {
            namespace,
            cwd: owned_cwd,
            files,
        })
    }

    fn open(&mut self, path: &str) -> Result<filesystem::OpenFile, ReplyStatus> {
        let metadata = self
            .namespace
            .borrow_mut()
            .metadata(&self.cwd, path)
            .map_err(application_filesystem_status)?;
        if metadata.kind != NodeKind::File {
            return Err(ReplyStatus::WrongType);
        }
        let index = if let Some(index) = self
            .files
            .iter()
            .position(|slot| slot.path.is_none() && !slot.retired)
        {
            index
        } else {
            if self.files.len() == filesystem::MAX_OPEN_FILES {
                return Err(ReplyStatus::Exhausted);
            }
            self.files
                .try_reserve(1)
                .map_err(|_| ReplyStatus::Exhausted)?;
            self.files.push(ApplicationFileSlot {
                generation: 1,
                retired: false,
                path: None,
                byte_count: 0,
            });
            self.files.len() - 1
        };
        let slot = self.files.get_mut(index).ok_or(ReplyStatus::Failure)?;
        if slot.generation > u32::from(u16::MAX) {
            slot.retired = true;
            return Err(ReplyStatus::Exhausted);
        }
        let mut owned_path = String::new();
        owned_path
            .try_reserve_exact(path.len())
            .map_err(|_| ReplyStatus::Exhausted)?;
        owned_path.push_str(path);
        slot.path = Some(owned_path);
        slot.byte_count = metadata.byte_count;
        let token =
            (slot.generation << 16) | u32::try_from(index + 1).map_err(|_| ReplyStatus::Failure)?;
        filesystem::OpenFile::new(token, metadata.byte_count).map_err(|_| ReplyStatus::Failure)
    }

    fn slot(
        files: &[ApplicationFileSlot],
        token: u32,
    ) -> Result<&ApplicationFileSlot, ReplyStatus> {
        let encoded_slot = token & u32::from(u16::MAX);
        let generation = token >> 16;
        if encoded_slot == 0 || generation == 0 {
            return Err(ReplyStatus::InvalidRequest);
        }
        let slot = files
            .get(usize::try_from(encoded_slot - 1).map_err(|_| ReplyStatus::InvalidRequest)?)
            .ok_or(ReplyStatus::InvalidRequest)?;
        if slot.generation != generation || slot.path.is_none() {
            return Err(ReplyStatus::InvalidRequest);
        }
        Ok(slot)
    }

    fn close(&mut self, token: u32) -> Result<(), ReplyStatus> {
        let encoded_slot = token & u32::from(u16::MAX);
        let generation = token >> 16;
        if encoded_slot == 0 || generation == 0 {
            return Err(ReplyStatus::InvalidRequest);
        }
        let slot = self
            .files
            .get_mut(usize::try_from(encoded_slot - 1).map_err(|_| ReplyStatus::InvalidRequest)?)
            .ok_or(ReplyStatus::InvalidRequest)?;
        if slot.generation != generation || slot.path.is_none() {
            return Err(ReplyStatus::InvalidRequest);
        }
        slot.path = None;
        slot.byte_count = 0;
        match slot.generation.checked_add(1) {
            Some(generation) if u16::try_from(generation).is_ok() => {
                slot.generation = generation;
            }
            _ => slot.retired = true,
        }
        Ok(())
    }
}

impl Service for ApplicationFilesystemService {
    #[allow(clippy::too_many_lines)]
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            filesystem::OPEN => {
                let Ok(path) = filesystem::decode_path_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let file = match self.open(path) {
                    Ok(file) => file,
                    Err(status) => return Ok(ServiceReply::empty(status)),
                };
                ServiceReply::with_payload(
                    ReplyStatus::Success,
                    &filesystem::encode_open_reply(file),
                )
            }
            filesystem::READ => {
                let Ok((token, offset, requested)) =
                    filesystem::decode_read_request(request.payload())
                else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let path = match Self::slot(&self.files, token)
                    .and_then(|slot| slot.path.as_deref().ok_or(ReplyStatus::InvalidRequest))
                {
                    Ok(path) => path,
                    Err(status) => return Ok(ServiceReply::empty(status)),
                };
                let mut bytes = [0_u8; troe_abi::MAX_SERVICE_PAYLOAD_BYTES];
                let count = match self.namespace.borrow_mut().read_file_at(
                    &self.cwd,
                    path,
                    offset,
                    &mut bytes[..requested],
                ) {
                    Ok(count) if count <= requested => count,
                    Ok(_) => return Ok(ServiceReply::empty(ReplyStatus::Corrupt)),
                    Err(error) => {
                        return Ok(ServiceReply::empty(application_filesystem_status(error)));
                    }
                };
                ServiceReply::with_payload(ReplyStatus::Success, &bytes[..count])
            }
            filesystem::CLOSE => {
                let Ok(token) = filesystem::decode_close_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match self.close(token) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(status) => Ok(ServiceReply::empty(status)),
                }
            }
            filesystem::LIST => {
                let Ok(decoded) = filesystem::decode_list_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let listing = match self.namespace.borrow_mut().list_bounded(
                    &self.cwd,
                    decoded.path,
                    decoded.cursor,
                    decoded.max_entries,
                    decoded.max_name_bytes,
                ) {
                    Ok(listing) => listing,
                    Err(error) => {
                        return Ok(ServiceReply::empty(application_filesystem_status(error)));
                    }
                };
                let mut entries = Vec::new();
                entries
                    .try_reserve_exact(listing.entries.len())
                    .map_err(|_| troe_dispatch::DispatchError::MetadataExhausted)?;
                for entry in &listing.entries {
                    entries.push(filesystem::DirectoryEntry {
                        kind: match entry.kind {
                            NodeKind::File => filesystem::NodeKind::File,
                            NodeKind::Directory => filesystem::NodeKind::Directory,
                            NodeKind::Symlink => filesystem::NodeKind::Symlink,
                        },
                        name: &entry.name,
                    });
                }
                let mut encoded = [0_u8; filesystem::MAX_LIST_REPLY_BYTES];
                let count =
                    filesystem::encode_list_reply(listing.next_cursor, &entries, &mut encoded)
                        .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &encoded[..count])
            }
            filesystem::METADATA | filesystem::METADATA_NO_FOLLOW => {
                let Ok(path) = filesystem::decode_path_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let metadata = match if request.opcode() == filesystem::METADATA {
                    self.namespace.borrow_mut().metadata(&self.cwd, path)
                } else {
                    self.namespace
                        .borrow_mut()
                        .metadata_no_follow(&self.cwd, path)
                } {
                    Ok(metadata) => metadata,
                    Err(error) => {
                        return Ok(ServiceReply::empty(application_filesystem_status(error)));
                    }
                };
                let metadata = filesystem::Metadata {
                    kind: match metadata.kind {
                        NodeKind::File => filesystem::NodeKind::File,
                        NodeKind::Directory => filesystem::NodeKind::Directory,
                        NodeKind::Symlink => filesystem::NodeKind::Symlink,
                    },
                    byte_count: metadata.byte_count,
                    modified_unix_seconds: metadata.modified_unix_seconds,
                    changed_unix_seconds: metadata.changed_unix_seconds,
                    created_unix_seconds: metadata.created_unix_seconds,
                };
                ServiceReply::with_payload(
                    ReplyStatus::Success,
                    &filesystem::encode_metadata_reply(metadata),
                )
            }
            filesystem::READ_LINK => {
                let Ok(path) = filesystem::decode_path_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let target = match self.namespace.borrow_mut().read_link(&self.cwd, path) {
                    Ok(target) => target,
                    Err(error) => {
                        return Ok(ServiceReply::empty(application_filesystem_status(error)));
                    }
                };
                let mut encoded = [0_u8; filesystem::MAX_LINK_BYTES];
                let count = filesystem::encode_link_reply(&target, &mut encoded)
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &encoded[..count])
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl ApplicationFilesystemMutationService {
    pub(crate) fn new(namespace: SharedNamespace, cwd: &str) -> Result<Self, ()> {
        let mut owned_cwd = String::new();
        owned_cwd.try_reserve_exact(cwd.len()).map_err(|_| ())?;
        owned_cwd.push_str(cwd);
        Ok(Self {
            namespace,
            cwd: owned_cwd,
            next_token: Some(1),
            pending: None,
        })
    }

    fn begin_replace(&mut self, path: &str) -> Result<u32, ReplyStatus> {
        if self.pending.is_some() {
            return Err(ReplyStatus::Conflict);
        }
        let token = self.next_token.ok_or(ReplyStatus::Exhausted)?;
        let mut owned_path = String::new();
        owned_path
            .try_reserve_exact(path.len())
            .map_err(|_| ReplyStatus::Exhausted)?;
        owned_path.push_str(path);
        self.namespace
            .borrow_mut()
            .truncate_file(&self.cwd, path)
            .map_err(application_filesystem_status)?;
        self.next_token = token.checked_add(1);
        self.pending = Some(PendingFileReplacement {
            token,
            path: owned_path,
            start_offset: 0,
            offset: 0,
            bytes: Vec::new(),
            chunk_bytes: FILE_IO_BUFFER_BYTES,
        });
        Ok(token)
    }

    fn begin_append(&mut self, path: &str) -> Result<(u32, u64), ReplyStatus> {
        if self.pending.is_some() {
            return Err(ReplyStatus::Conflict);
        }
        let metadata = self
            .namespace
            .borrow_mut()
            .metadata(&self.cwd, path)
            .map_err(application_filesystem_status)?;
        if metadata.kind != NodeKind::File {
            return Err(ReplyStatus::WrongType);
        }
        let token = self.next_token.ok_or(ReplyStatus::Exhausted)?;
        let mut owned_path = String::new();
        owned_path
            .try_reserve_exact(path.len())
            .map_err(|_| ReplyStatus::Exhausted)?;
        owned_path.push_str(path);
        self.next_token = token.checked_add(1);
        self.pending = Some(PendingFileReplacement {
            token,
            path: owned_path,
            start_offset: metadata.byte_count,
            offset: metadata.byte_count,
            bytes: Vec::new(),
            chunk_bytes: FILE_IO_BUFFER_BYTES,
        });
        Ok((token, metadata.byte_count))
    }

    fn append(
        &mut self,
        append: filesystem_mutation::AppendRequest<'_>,
    ) -> Result<(), ReplyStatus> {
        let pending = self.pending.as_mut().ok_or(ReplyStatus::InvalidRequest)?;
        if pending.token != append.token || pending.offset != append.offset {
            return Err(ReplyStatus::InvalidRequest);
        }
        pending
            .bytes
            .try_reserve_exact(append.bytes.len())
            .map_err(|_| ReplyStatus::Exhausted)?;
        pending.bytes.extend_from_slice(append.bytes);
        pending.offset = pending
            .offset
            .checked_add(u64::try_from(append.bytes.len()).map_err(|_| ReplyStatus::Overflow)?)
            .ok_or(ReplyStatus::Overflow)?;
        if pending.bytes.len() >= pending.chunk_bytes {
            self.namespace
                .borrow_mut()
                .append_file(&self.cwd, &pending.path, &pending.bytes)
                .map_err(application_filesystem_status)?;
            pending.bytes.clear();
        }
        Ok(())
    }

    fn read_replacement(
        &mut self,
        token: u32,
        offset: u64,
        destination: &mut [u8],
    ) -> Result<usize, ReplyStatus> {
        let pending = self.pending.as_mut().ok_or(ReplyStatus::InvalidRequest)?;
        if pending.token != token || offset > pending.offset {
            return Err(ReplyStatus::InvalidRequest);
        }
        // Reads observe every staged byte, so flush the aggregation buffer
        // before consulting the streamed file.
        if !pending.bytes.is_empty() {
            self.namespace
                .borrow_mut()
                .append_file(&self.cwd, &pending.path, &pending.bytes)
                .map_err(application_filesystem_status)?;
            pending.bytes.clear();
        }
        let available = pending.offset - offset;
        let limit = usize::try_from(available).unwrap_or(usize::MAX);
        let count = destination.len().min(limit);
        if count == 0 {
            return Ok(0);
        }
        let path = pending.path.clone();
        self.namespace
            .borrow_mut()
            .read_file_at(&self.cwd, &path, offset, &mut destination[..count])
            .map_err(application_filesystem_status)
    }

    fn set_chunk_size(&mut self, token: u32, bytes: usize) -> Result<(), ReplyStatus> {
        let pending = self.pending.as_mut().ok_or(ReplyStatus::InvalidRequest)?;
        if pending.token != token
            || pending.offset != pending.start_offset
            || !pending.bytes.is_empty()
        {
            return Err(ReplyStatus::InvalidRequest);
        }
        pending.chunk_bytes = bytes;
        Ok(())
    }

    fn finish(&mut self, token: u32, commit: bool) -> Result<(), ReplyStatus> {
        let Some(pending) = self.pending.take() else {
            return Err(ReplyStatus::InvalidRequest);
        };
        if pending.token != token {
            self.pending = Some(pending);
            return Err(ReplyStatus::InvalidRequest);
        }
        if !commit {
            return Ok(());
        }
        let mut namespace = self.namespace.borrow_mut();
        if !pending.bytes.is_empty() {
            namespace
                .append_file(&self.cwd, &pending.path, &pending.bytes)
                .map_err(application_filesystem_status)?;
        }
        namespace
            .sync_file(&self.cwd, &pending.path)
            .map_err(application_filesystem_status)
    }

    fn remove(&mut self, path: &str) -> Result<(), ReplyStatus> {
        if self.pending.is_some() {
            return Err(ReplyStatus::Conflict);
        }
        self.namespace
            .borrow_mut()
            .remove_file(&self.cwd, path)
            .map_err(application_filesystem_status)
    }

    fn create_symlink(&mut self, target: &str, link_path: &str) -> Result<(), ReplyStatus> {
        if self.pending.is_some() {
            return Err(ReplyStatus::Conflict);
        }
        self.namespace
            .borrow_mut()
            .create_symlink(&self.cwd, target, link_path)
            .map_err(application_filesystem_status)
    }

    fn create_hard_link(&mut self, existing: &str, new_path: &str) -> Result<(), ReplyStatus> {
        if self.pending.is_some() {
            return Err(ReplyStatus::Conflict);
        }
        self.namespace
            .borrow_mut()
            .create_hard_link(&self.cwd, existing, new_path)
            .map_err(application_filesystem_status)
    }

    fn create_directory(&mut self, path: &str) -> Result<(), ReplyStatus> {
        if self.pending.is_some() {
            return Err(ReplyStatus::Conflict);
        }
        self.namespace
            .borrow_mut()
            .create_directory(&self.cwd, path)
            .map_err(application_filesystem_status)
    }

    fn remove_directory(&mut self, path: &str) -> Result<(), ReplyStatus> {
        if self.pending.is_some() {
            return Err(ReplyStatus::Conflict);
        }
        self.namespace
            .borrow_mut()
            .remove_directory(&self.cwd, path)
            .map_err(application_filesystem_status)
    }

    fn set_modified_time(
        &mut self,
        path: &str,
        unix_seconds: Option<u64>,
    ) -> Result<(), ReplyStatus> {
        if self.pending.is_some() {
            return Err(ReplyStatus::Conflict);
        }
        self.namespace
            .borrow_mut()
            .set_modified_time(&self.cwd, path, unix_seconds)
            .map_err(application_filesystem_status)
    }

    fn rename(&mut self, source: &str, destination: &str) -> Result<(), ReplyStatus> {
        if self.pending.is_some() {
            return Err(ReplyStatus::Conflict);
        }
        self.namespace
            .borrow_mut()
            .rename(&self.cwd, source, destination)
            .map_err(application_filesystem_status)
    }
}

impl Service for ApplicationFilesystemMutationService {
    #[allow(clippy::too_many_lines)]
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            filesystem_mutation::BEGIN_REPLACE => {
                let Ok(path) = filesystem_mutation::decode_path_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let token = match self.begin_replace(path) {
                    Ok(token) => token,
                    Err(status) => return Ok(ServiceReply::empty(status)),
                };
                let reply = filesystem_mutation::encode_token(token)
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &reply)
            }
            filesystem_mutation::BEGIN_APPEND => {
                let Ok(path) = filesystem_mutation::decode_path_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let (token, offset) = match self.begin_append(path) {
                    Ok(result) => result,
                    Err(status) => return Ok(ServiceReply::empty(status)),
                };
                let reply = filesystem_mutation::encode_begin_append_reply(token, offset)
                    .map_err(|_| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &reply)
            }
            filesystem_mutation::APPEND => {
                let Ok(append) = filesystem_mutation::decode_append_request(request.payload())
                else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match self.append(append) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(status) => Ok(ServiceReply::empty(status)),
                }
            }
            filesystem_mutation::READ_REPLACEMENT => {
                let Ok((token, offset, length)) =
                    filesystem_mutation::decode_read_request(request.payload())
                else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let mut staged = [0_u8; filesystem_mutation::MAX_READ_BYTES];
                let limit = length.min(staged.len());
                let count = match self.read_replacement(token, offset, &mut staged[..limit]) {
                    Ok(count) => count,
                    Err(status) => return Ok(ServiceReply::empty(status)),
                };
                ServiceReply::with_payload(ReplyStatus::Success, &staged[..count])
            }
            filesystem_mutation::SET_CHUNK_SIZE => {
                let Ok((token, bytes)) =
                    filesystem_mutation::decode_chunk_size_request(request.payload())
                else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match self.set_chunk_size(token, bytes) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(status) => Ok(ServiceReply::empty(status)),
                }
            }
            filesystem_mutation::COMMIT_REPLACE | filesystem_mutation::ABORT_REPLACE => {
                let Ok(token) = filesystem_mutation::decode_token(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let commit = request.opcode() == filesystem_mutation::COMMIT_REPLACE;
                match self.finish(token, commit) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(status) => Ok(ServiceReply::empty(status)),
                }
            }
            filesystem_mutation::REMOVE => {
                let Ok(path) = filesystem_mutation::decode_path_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match self.remove(path) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(status) => Ok(ServiceReply::empty(status)),
                }
            }
            filesystem_mutation::CREATE_SYMLINK | filesystem_mutation::CREATE_HARD_LINK => {
                let Ok(link) = filesystem_mutation::decode_link_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let result = if request.opcode() == filesystem_mutation::CREATE_SYMLINK {
                    self.create_symlink(link.target, link.link_path)
                } else {
                    self.create_hard_link(link.target, link.link_path)
                };
                match result {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(status) => Ok(ServiceReply::empty(status)),
                }
            }
            filesystem_mutation::CREATE_DIRECTORY => {
                let Ok(path) = filesystem_mutation::decode_path_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                match self.create_directory(path) {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(status) => Ok(ServiceReply::empty(status)),
                }
            }
            filesystem_mutation::REMOVE_DIRECTORY => {
                let Ok(path) = filesystem_mutation::decode_path_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                Ok(application_mutation_reply(self.remove_directory(path)))
            }
            filesystem_mutation::SET_MODIFIED_TIME => {
                let Ok((path, unix_seconds)) =
                    filesystem_mutation::decode_set_modified_time_request(request.payload())
                else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                Ok(application_mutation_reply(
                    self.set_modified_time(path, unix_seconds),
                ))
            }
            filesystem_mutation::RENAME => {
                let Ok(paths) = filesystem_mutation::decode_two_path_request(request.payload())
                else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                Ok(application_mutation_reply(
                    self.rename(paths.source, paths.destination),
                ))
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

impl Service for ApplicationVolumeControlService {
    fn call(&mut self, request: Request<'_>) -> Result<ServiceReply, troe_dispatch::DispatchError> {
        match request.opcode() {
            volume_control::LIST if request.payload().is_empty() => {
                let mut reply = [0_u8; volume_control::MAX_LIST_REPLY_BYTES];
                let count = self
                    .mounts
                    .borrow()
                    .encode_list(&mut reply)
                    .map_err(|()| troe_dispatch::DispatchError::AccountingOverflow)?;
                ServiceReply::with_payload(ReplyStatus::Success, &reply[..count])
            }
            volume_control::ACTIVATE => {
                let Ok(name) = volume_control::decode_activate_request(request.payload()) else {
                    return Ok(ServiceReply::empty(ReplyStatus::InvalidRequest));
                };
                let status = self
                    .mounts
                    .borrow_mut()
                    .activate(name, &mut self.namespace.borrow_mut());
                match status {
                    Ok(()) => Ok(ServiceReply::empty(ReplyStatus::Success)),
                    Err(status) => Ok(ServiceReply::empty(status)),
                }
            }
            _ => Ok(ServiceReply::empty(ReplyStatus::InvalidRequest)),
        }
    }
}

pub(crate) const fn application_filesystem_status(error: FsError) -> ReplyStatus {
    match error {
        FsError::Invalid => ReplyStatus::InvalidPath,
        FsError::NotFound => ReplyStatus::NotFound,
        FsError::WrongType => ReplyStatus::WrongType,
        FsError::ReadOnly => ReplyStatus::ReadOnly,
        FsError::NoSpace => ReplyStatus::NoSpace,
        FsError::Overflow => ReplyStatus::Overflow,
        FsError::Exists => ReplyStatus::Exists,
        FsError::Corrupt => ReplyStatus::Corrupt,
        FsError::Io => ReplyStatus::Io,
        FsError::Unsupported => ReplyStatus::Unsupported,
        FsError::NotConfigured => ReplyStatus::NotConfigured,
        FsError::NotEmpty => ReplyStatus::NotEmpty,
        FsError::CrossDevice => ReplyStatus::CrossDevice,
    }
}

pub(crate) fn application_mutation_reply(result: Result<(), ReplyStatus>) -> ServiceReply {
    ServiceReply::empty(match result {
        Ok(()) => ReplyStatus::Success,
        Err(status) => status,
    })
}
