//! Completion activation registry for embedded package artifacts and intrinsics.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use troe_application::{KEX_PACKAGE_V1_HEADER_BYTES, kex_package_completion_range};
use troe_completion::{
    AddressConstraints, ArgumentCondition, ArgumentPosition, ArtifactResolver, CompletionArtifact,
    CompletionDescriptor, CompletionRequest, CompletionResolution, CompletionRule, DescriptorError,
    IntegerConstraints, PathConstraints, PathKind, PrefixPredicate, Resolver, ValidatedDescriptor,
};
use troe_fs_api::{FsError, NodeKind};
use troe_fs_client::NamespaceClient;

const REGISTRY_MAX_ENTRIES: usize = 1024;
const REGISTRY_MAX_BYTES: usize = 1024 * 1024;
const REGISTRY_PAGE_ENTRIES: usize = 64;
const REGISTRY_PAGE_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageEntry {
    command: String,
    artifact: CompletionArtifact,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ActiveResolver {
    Values(Vec<String>),
    Path(PathConstraints),
    Command,
    Address(AddressConstraints),
    Integer(IntegerConstraints),
    Job,
    Service,
    Volume,
}

/// Exact active-generation registry reconstructed from embedded package data.
#[derive(Debug)]
pub(crate) struct PackageCompletionRegistry {
    revision: Option<u64>,
    entries: Vec<PackageEntry>,
}

impl PackageCompletionRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            revision: None,
            entries: Vec::new(),
        }
    }

    pub(crate) fn refresh(&mut self, namespace: &mut dyn NamespaceClient) {
        let revision = namespace.command_revision();
        if self.revision == Some(revision) {
            return;
        }
        if let Ok(entries) = load_package_registry(namespace) {
            self.entries = entries;
            self.revision = Some(revision);
        }
    }

    pub(crate) fn resolve(
        &self,
        command: &str,
        request: CompletionRequest<'_>,
    ) -> Option<ActiveResolver> {
        self.entries
            .binary_search_by(|entry| entry.command.as_str().cmp(command))
            .ok()
            .and_then(|index| self.entries[index].artifact.evaluate(request))
            .map(|resolution| match resolution.resolver() {
                ArtifactResolver::Values(values) => ActiveResolver::Values(values.to_vec()),
                ArtifactResolver::Path(value) => ActiveResolver::Path(value),
                ArtifactResolver::Command => ActiveResolver::Command,
                ArtifactResolver::Address(value) => ActiveResolver::Address(value),
                ArtifactResolver::Integer(value) => ActiveResolver::Integer(value),
                ArtifactResolver::Job => ActiveResolver::Job,
                ArtifactResolver::Service => ActiveResolver::Service,
                ArtifactResolver::Volume => ActiveResolver::Volume,
            })
    }
}

fn load_package_registry(
    namespace: &mut dyn NamespaceClient,
) -> Result<Vec<PackageEntry>, FsError> {
    let mut entries = Vec::new();
    let mut cursor = 0_u64;
    let mut retained_bytes = 0_usize;
    let mut scanned = 0_usize;
    loop {
        let page = match namespace.list_bounded(
            "/",
            "/bin",
            cursor,
            REGISTRY_PAGE_ENTRIES,
            REGISTRY_PAGE_BYTES,
        ) {
            Ok(page) => page,
            Err(FsError::NotFound) => break,
            Err(error) => return Err(error),
        };
        let page_len = page.entries.len();
        for entry in page.entries {
            scanned = scanned.checked_add(1).ok_or(FsError::Overflow)?;
            if scanned > REGISTRY_MAX_ENTRIES {
                return Err(FsError::NoSpace);
            }
            if entry.kind != NodeKind::File {
                continue;
            }
            let Some(command) = entry
                .name
                .strip_suffix(".kex")
                .filter(|name| valid_command(name))
            else {
                continue;
            };
            let path = alloc::format!("/bin/{}", entry.name);
            let metadata = namespace.metadata("/", &path)?;
            let mut header = [0_u8; KEX_PACKAGE_V1_HEADER_BYTES];
            if namespace.read_file_at("/", &path, 0, &mut header)? != header.len() {
                continue;
            }
            let Some((offset, completion_bytes)) =
                kex_package_completion_range(&header, metadata.byte_count)
                    .ok()
                    .flatten()
            else {
                continue;
            };
            let next_bytes = retained_bytes
                .checked_add(command.len())
                .and_then(|value| value.checked_add(completion_bytes))
                .ok_or(FsError::Overflow)?;
            if next_bytes > REGISTRY_MAX_BYTES {
                return Err(FsError::NoSpace);
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(completion_bytes)
                .map_err(|_| FsError::NoSpace)?;
            bytes.resize(completion_bytes, 0);
            if namespace.read_file_at("/", &path, offset, &mut bytes)? != completion_bytes {
                continue;
            }
            let Ok(artifact) = CompletionArtifact::parse(&bytes) else {
                continue;
            };
            if artifact.command() != command {
                continue;
            }
            entries.try_reserve(1).map_err(|_| FsError::NoSpace)?;
            entries.push(PackageEntry {
                command: command.to_string(),
                artifact,
            });
            retained_bytes = next_bytes;
        }
        match page.next_cursor {
            Some(next) if next != cursor && page_len != 0 => cursor = next,
            Some(_) => return Err(FsError::Corrupt),
            None => break,
        }
    }
    entries.sort_unstable_by(|left, right| left.command.cmp(&right.command));
    entries.dedup_by(|left, right| left.command == right.command);
    Ok(entries)
}

fn valid_command(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

const EMPTY: &[ArgumentCondition<'_>] = &[];
const SERVICE_STATUS: &[ArgumentCondition<'_>] = &[ArgumentCondition::Equals {
    index: 0,
    value: "status",
}];
const SERVICE_START: &[ArgumentCondition<'_>] = &[ArgumentCondition::Equals {
    index: 0,
    value: "start",
}];
const SERVICE_STOP: &[ArgumentCondition<'_>] = &[ArgumentCondition::Equals {
    index: 0,
    value: "stop",
}];
const SERVICE_RESTART: &[ArgumentCondition<'_>] = &[ArgumentCondition::Equals {
    index: 0,
    value: "restart",
}];
const SERVICE_LOG: &[ArgumentCondition<'_>] = &[ArgumentCondition::Equals {
    index: 0,
    value: "log",
}];
const SERVICE_OPERATIONS: &[&str] = &["list", "log", "restart", "start", "status", "stop"];
const DIRECTORY: Resolver<'_> = Resolver::Path(PathConstraints::new(PathKind::Directory));
const CD_RULES: &[CompletionRule<'_>] = &[CompletionRule::new(
    ArgumentPosition::exact(1),
    PrefixPredicate::Any,
    EMPTY,
    DIRECTORY,
)];
const JOB_RULES: &[CompletionRule<'_>] = &[CompletionRule::new(
    ArgumentPosition::exact(1),
    PrefixPredicate::Any,
    EMPTY,
    Resolver::Job,
)];
const SVC_RULES: &[CompletionRule<'_>] = &[
    CompletionRule::new(
        ArgumentPosition::exact(1),
        PrefixPredicate::Any,
        EMPTY,
        Resolver::Values(SERVICE_OPERATIONS),
    ),
    CompletionRule::new(
        ArgumentPosition::exact(2),
        PrefixPredicate::Any,
        SERVICE_STATUS,
        Resolver::Service,
    ),
    CompletionRule::new(
        ArgumentPosition::exact(2),
        PrefixPredicate::Any,
        SERVICE_START,
        Resolver::Service,
    ),
    CompletionRule::new(
        ArgumentPosition::exact(2),
        PrefixPredicate::Any,
        SERVICE_STOP,
        Resolver::Service,
    ),
    CompletionRule::new(
        ArgumentPosition::exact(2),
        PrefixPredicate::Any,
        SERVICE_RESTART,
        Resolver::Service,
    ),
    CompletionRule::new(
        ArgumentPosition::exact(2),
        PrefixPredicate::Any,
        SERVICE_LOG,
        Resolver::Service,
    ),
];
const INTRINSICS: &[(&str, CompletionDescriptor<'_>)] = &[
    ("cd", CompletionDescriptor::new(CD_RULES)),
    ("fg", CompletionDescriptor::new(JOB_RULES)),
    ("kill", CompletionDescriptor::new(JOB_RULES)),
    ("log", CompletionDescriptor::new(JOB_RULES)),
    ("svc", CompletionDescriptor::new(SVC_RULES)),
    ("wait", CompletionDescriptor::new(JOB_RULES)),
];

#[derive(Clone, Copy, Debug)]
struct IntrinsicEntry {
    command: &'static str,
    descriptor: ValidatedDescriptor<'static>,
}

/// Immutable descriptors for shell-owned intrinsics only.
#[derive(Debug)]
pub(crate) struct IntrinsicCompletionRegistry {
    entries: [IntrinsicEntry; INTRINSICS.len()],
}

impl IntrinsicCompletionRegistry {
    pub(crate) fn new() -> Result<Self, DescriptorError> {
        let mut entries = [IntrinsicEntry {
            command: "",
            descriptor: CompletionDescriptor::new(&[]).validate()?,
        }; INTRINSICS.len()];
        for (index, (command, descriptor)) in INTRINSICS.iter().copied().enumerate() {
            entries[index] = IntrinsicEntry {
                command,
                descriptor: descriptor.validate()?,
            };
        }
        Ok(Self { entries })
    }

    pub(crate) fn resolve(
        &self,
        command: &str,
        request: CompletionRequest<'_>,
    ) -> Option<CompletionResolution<'static>> {
        self.entries
            .iter()
            .find(|entry| entry.command == command)
            .and_then(|entry| entry.descriptor.evaluate(request))
    }
}

#[cfg(test)]
mod tests {
    use super::{INTRINSICS, IntrinsicCompletionRegistry};

    #[test]
    fn intrinsic_registry_is_sorted_unique_and_valid() {
        let _registry =
            IntrinsicCompletionRegistry::new().unwrap_or_else(|_| std::process::abort());
        assert!(
            INTRINSICS
                .windows(2)
                .all(|entries| entries[0].0 < entries[1].0)
        );
    }
}
