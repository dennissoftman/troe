//! Portable validation for one bounded native root-generation activation.

use troe_fmt_cspk::{ContentDigest, ContentPack, GenerationManifest, ObjectKind, SecurityManifest};
use troe_fmt_scfg::{
    ActivationPointer, ConfigReference, FailureAction, SystemConfig, parse_config,
};
use troe_identity::{
    IdentityLimits, IdentitySnapshot, MountIdentityMode, validate_snapshot, validate_successor,
};

/// Fully validated generation metadata retained by the activation selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedRootActivation {
    generation: u64,
    health_rollback: bool,
}

impl ValidatedRootActivation {
    /// Selected SCFG generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Whether one service health action targets the selected predecessor.
    #[must_use]
    pub const fn health_rollback(self) -> bool {
        self.health_rollback
    }
}

/// Stable fail-closed reason for rejecting one root activation candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationValidationError {
    /// The SCFG reference or its unique generation manifest did not resolve exactly.
    Reference,
    /// SCFG, GMAN, and predecessor policy did not describe the same bounded chain.
    Policy,
    /// One typed identity snapshot was absent, malformed, or unsuitable for the root role.
    Identity,
    /// The active identity snapshot was not a valid successor to its predecessor.
    Transition,
    /// The unique bounded GC-root graph was incomplete or inconsistent.
    Graph,
}

struct ResolvedGeneration {
    manifest_digest: ContentDigest,
    manifest: GenerationManifest,
    config: SystemConfig,
    identity: IdentitySnapshot,
}

/// Validate one complete active/predecessor root-generation candidate.
///
/// Both generations independently resolve through exact SCFG, GMAN, ISEC, and
/// typed identity-object identities. A two-generation pointer additionally
/// proves the predecessor links and permanent identity-successor invariants.
///
/// # Errors
///
/// Rejects unresolved or ambiguous references, inconsistent rollback policy,
/// invalid identity snapshots/transitions, and incomplete or excessive root
/// graphs. No partial activation authority is returned.
pub fn validate_root_activation(
    content: &ContentPack<'_>,
    pointer: ActivationPointer,
    identity_limits: IdentityLimits,
) -> Result<ValidatedRootActivation, GenerationValidationError> {
    let active = resolve_generation(content, pointer.active(), identity_limits)?;
    let health_rollback = active
        .config
        .services()
        .iter()
        .any(|service| service.failure_action() == FailureAction::PreviousGeneration);
    let expected_roots = if let Some(previous) = pointer.previous() {
        let previous = resolve_generation(content, previous, identity_limits)?;
        if active.manifest.previous() != Some(previous.manifest_digest)
            || active.config.previous_generation() != Some(previous.config.generation())
            || !active.config.recovery().fallback_previous()
            || previous.manifest.previous().is_some()
            || previous.config.previous_generation().is_some()
            || previous.config.recovery().fallback_previous()
            || previous
                .config
                .services()
                .iter()
                .any(|service| service.failure_action() == FailureAction::PreviousGeneration)
        {
            return Err(GenerationValidationError::Policy);
        }
        validate_successor(&previous.identity, &active.identity)
            .map_err(|_| GenerationValidationError::Transition)?;
        // Six generation-bound objects must differ. The ACL may be shared
        // unchanged or may be a distinct validated successor.
        13..=14
    } else {
        if active.manifest.previous().is_some()
            || active.config.previous_generation().is_some()
            || active.config.recovery().fallback_previous()
            || health_rollback
        {
            return Err(GenerationValidationError::Policy);
        }
        7..=7
    };
    let roots = content
        .generation_roots(active.manifest_digest, 2)
        .map_err(|_| GenerationValidationError::Graph)?;
    if !expected_roots.contains(&roots.len()) {
        return Err(GenerationValidationError::Graph);
    }
    Ok(ValidatedRootActivation {
        generation: active.config.generation(),
        health_rollback,
    })
}

fn resolve_generation(
    content: &ContentPack<'_>,
    reference: ConfigReference,
    identity_limits: IdentityLimits,
) -> Result<ResolvedGeneration, GenerationValidationError> {
    let config_object = content
        .get(reference.digest())
        .ok_or(GenerationValidationError::Reference)?;
    if config_object.kind != ObjectKind::SystemConfig || !reference.matches(config_object.bytes) {
        return Err(GenerationValidationError::Reference);
    }
    let config =
        parse_config(config_object.bytes).map_err(|_| GenerationValidationError::Reference)?;
    let mut found = None;
    for object in content.objects() {
        if object.kind != ObjectKind::GenerationManifest {
            continue;
        }
        let manifest = GenerationManifest::parse(object.bytes)
            .map_err(|_| GenerationValidationError::Reference)?;
        if manifest.generation() == reference.generation()
            && manifest.config() == reference.digest()
            && found.replace((object.digest, manifest)).is_some()
        {
            return Err(GenerationValidationError::Reference);
        }
    }
    let (manifest_digest, manifest) = found.ok_or(GenerationValidationError::Reference)?;
    let identity = validate_generation_security(content, manifest, identity_limits)?;
    Ok(ResolvedGeneration {
        manifest_digest,
        manifest,
        config,
        identity,
    })
}

fn validate_generation_security(
    content: &ContentPack<'_>,
    generation: GenerationManifest,
    identity_limits: IdentityLimits,
) -> Result<IdentitySnapshot, GenerationValidationError> {
    let security = content
        .get(
            generation
                .security()
                .ok_or(GenerationValidationError::Identity)?,
        )
        .ok_or(GenerationValidationError::Identity)?;
    if security.kind != ObjectKind::SecurityManifest {
        return Err(GenerationValidationError::Identity);
    }
    let security =
        SecurityManifest::parse(security.bytes).map_err(|_| GenerationValidationError::Identity)?;
    if security.generation() != generation.generation() {
        return Err(GenerationValidationError::Identity);
    }
    let registry = content
        .get(security.registry())
        .ok_or(GenerationValidationError::Identity)?;
    let mapping = content
        .get(security.mapping())
        .ok_or(GenerationValidationError::Identity)?;
    let mount = content
        .get(security.mount())
        .ok_or(GenerationValidationError::Identity)?;
    let acl = content
        .get(security.acl())
        .ok_or(GenerationValidationError::Identity)?;
    if registry.kind != ObjectKind::IdentityRegistry
        || mapping.kind != ObjectKind::IdentityMapping
        || mount.kind != ObjectKind::MountPolicy
        || acl.kind != ObjectKind::NativeAcl
    {
        return Err(GenerationValidationError::Identity);
    }
    let snapshot = validate_snapshot(
        registry.bytes,
        mapping.bytes,
        mount.bytes,
        acl.bytes,
        generation.generation(),
        identity_limits,
    )
    .map_err(|_| GenerationValidationError::Identity)?;
    if snapshot.mount.role() != "root"
        || snapshot.mount.mode() != MountIdentityMode::ExplicitMapping
        || !snapshot.mount.raw_metadata_lossless()
    {
        return Err(GenerationValidationError::Identity);
    }
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{GenerationValidationError, validate_root_activation};
    use troe_fmt_cspk::{ContentDigest, ContentPack, GenerationManifest, ObjectKind};
    use troe_fmt_scfg::{
        ActivationPointer, ActivationRecovery, ConfigReference, recover_activation,
    };
    use troe_identity::IdentityLimits;

    const CONTENT: &[u8] = include_bytes!("../../../../assets/system.cspk");
    const ACTIVATION: &[u8] = include_bytes!("../../../../assets/system.sact");
    const ACTIVE_CONFIG: &[u8] = include_bytes!("../../../../assets/system.scfg");
    const PREVIOUS_CONFIG: &[u8] = include_bytes!("../../../../assets/system-prev.scfg");

    fn fixture() -> Result<(ContentPack<'static>, ActivationPointer), GenerationValidationError> {
        let content =
            ContentPack::parse(CONTENT).map_err(|_| GenerationValidationError::Reference)?;
        let pointer = ActivationPointer::parse(ACTIVATION)
            .map_err(|_| GenerationValidationError::Reference)?;
        Ok((content, pointer))
    }

    fn altered_reference(bytes: &[u8]) -> Result<ConfigReference, GenerationValidationError> {
        let mut altered = Vec::from(bytes);
        let last = altered
            .last_mut()
            .ok_or(GenerationValidationError::Reference)?;
        *last = if *last == b'y' { b'z' } else { b'y' };
        altered[20..24].fill(0);
        let checksum = crc32(&altered);
        altered[20..24].copy_from_slice(&checksum.to_le_bytes());
        ConfigReference::from_bytes(&altered).map_err(|_| GenerationValidationError::Reference)
    }

    #[test]
    fn production_fixture_validates_with_unique_deterministic_roots()
    -> Result<(), GenerationValidationError> {
        let (content, pointer) = fixture()?;
        let validated = validate_root_activation(&content, pointer, IdentityLimits::standard())?;
        assert_eq!(validated.generation(), 2);
        assert!(validated.health_rollback());

        let manifest_digest = content
            .objects()
            .find_map(|object| {
                if object.kind != ObjectKind::GenerationManifest {
                    return None;
                }
                let manifest = GenerationManifest::parse(object.bytes).ok()?;
                (manifest.generation() == pointer.active().generation()).then_some(object.digest)
            })
            .ok_or(GenerationValidationError::Graph)?;
        let roots = content
            .generation_roots(manifest_digest, 2)
            .map_err(|_| GenerationValidationError::Graph)?;
        assert_eq!(roots.len(), 13);
        assert_eq!(
            roots,
            content
                .generation_roots(manifest_digest, 2)
                .map_err(|_| GenerationValidationError::Graph)?
        );
        for (index, root) in roots.iter().enumerate() {
            assert!(!roots[..index].contains(root));
        }
        Ok(())
    }

    #[test]
    fn invalid_active_recovers_only_the_named_predecessor() -> Result<(), GenerationValidationError>
    {
        let (content, published) = fixture()?;
        let invalid_active = altered_reference(ACTIVE_CONFIG)?;
        let pointer = ActivationPointer::new(invalid_active, published.previous())
            .map_err(|_| GenerationValidationError::Policy)?;
        let recovered = recover_activation(pointer, |candidate| {
            validate_root_activation(&content, candidate, IdentityLimits::standard())
        });
        let ActivationRecovery::Previous { pointer, validated } = recovered else {
            return Err(GenerationValidationError::Policy);
        };
        assert_eq!(
            pointer.active(),
            published
                .previous()
                .ok_or(GenerationValidationError::Policy)?
        );
        assert_eq!(validated.generation(), 1);
        assert!(!validated.health_rollback());
        Ok(())
    }

    #[test]
    fn invalid_active_and_predecessor_fail_closed() -> Result<(), GenerationValidationError> {
        let (content, _published) = fixture()?;
        let invalid_active = altered_reference(ACTIVE_CONFIG)?;
        let invalid_previous = altered_reference(PREVIOUS_CONFIG)?;
        let pointer = ActivationPointer::new(invalid_active, Some(invalid_previous))
            .map_err(|_| GenerationValidationError::Policy)?;
        assert!(matches!(
            recover_activation(pointer, |candidate| validate_root_activation(
                &content,
                candidate,
                IdentityLimits::standard(),
            )),
            ActivationRecovery::Unavailable
        ));
        Ok(())
    }

    fn crc32(bytes: &[u8]) -> u32 {
        troe_checksum::crc32(bytes)
    }

    #[test]
    fn altered_references_are_valid_but_absent_from_the_pack()
    -> Result<(), GenerationValidationError> {
        let (content, _) = fixture()?;
        for reference in [
            altered_reference(ACTIVE_CONFIG)?,
            altered_reference(PREVIOUS_CONFIG)?,
        ] {
            assert!(content.get(reference.digest()).is_none());
            assert_ne!(reference.digest(), ContentDigest::of(b""));
        }
        Ok(())
    }
}
