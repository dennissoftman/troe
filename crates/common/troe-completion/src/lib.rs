//! Bounded declarative completion descriptors and semantic resolver requests.
//!
//! A descriptor selects a trusted resolver from parsed shell context. Literal
//! sets are retained directly, while open domains such as files, addresses,
//! jobs, and services remain shell-side resolver requests. This crate neither
//! reads a namespace nor executes an application.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Maximum rules accepted in one application descriptor.
pub const MAX_DESCRIPTOR_RULES: usize = 64;
/// Maximum argument conditions accepted by one rule.
pub const MAX_RULE_CONDITIONS: usize = 8;
/// Maximum literal candidates retained by one value resolver.
pub const MAX_LITERAL_VALUES: usize = 64;
/// Maximum bytes retained across one value resolver's literal candidates.
pub const MAX_LITERAL_BYTES: usize = 4 * 1024;
/// Maximum bytes accepted in one descriptor predicate or literal value.
pub const MAX_TEXT_BYTES: usize = 512;
/// Maximum parsed arguments accepted in one completion request.
pub const MAX_REQUEST_ARGUMENTS: usize = 128;
/// Maximum bytes retained by references in one completion request.
pub const MAX_REQUEST_TEXT_BYTES: usize = 16 * 1024;
/// Maximum bytes in one canonical embedded CMPL artifact.
pub const MAX_ARTIFACT_BYTES: usize = 16 * 1024;
/// Maximum bytes in the command identity bound by a CMPL artifact.
pub const MAX_COMMAND_BYTES: usize = 64;

/// Invalid caller-selected candidate budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionLimitsError {
    /// Candidate count and byte budgets must both be zero or both be nonzero.
    InconsistentCapacity,
}

/// Shell-owned limits supplied to a declarative or dynamic resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionLimits {
    max_candidates: usize,
    max_bytes: usize,
}

impl CompletionLimits {
    /// Construct matching candidate-count and candidate-byte budgets.
    ///
    /// Two zero values explicitly disable completion.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionLimitsError::InconsistentCapacity`] when exactly
    /// one capacity is zero.
    pub const fn new(
        max_candidates: usize,
        max_bytes: usize,
    ) -> Result<Self, CompletionLimitsError> {
        if (max_candidates == 0) != (max_bytes == 0) {
            return Err(CompletionLimitsError::InconsistentCapacity);
        }
        Ok(Self {
            max_candidates,
            max_bytes,
        })
    }

    /// Maximum candidates a resolver may return.
    #[must_use]
    pub const fn max_candidates(self) -> usize {
        self.max_candidates
    }

    /// Maximum candidate payload bytes a resolver may return.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Whether both capacities disable completion.
    #[must_use]
    pub const fn is_disabled(self) -> bool {
        self.max_candidates == 0
    }
}

/// Argument-position selector for one ordered completion rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArgumentPosition {
    minimum: u8,
    maximum: u8,
}

impl ArgumentPosition {
    /// Match one exact one-based argument position.
    #[must_use]
    pub const fn exact(position: u8) -> Self {
        Self {
            minimum: position,
            maximum: position,
        }
    }

    /// Match one argument position and every position after it.
    #[must_use]
    pub const fn at_least(position: u8) -> Self {
        Self {
            minimum: position,
            maximum: u8::MAX,
        }
    }

    /// Match an inclusive range of one-based argument positions.
    #[must_use]
    pub const fn inclusive(minimum: u8, maximum: u8) -> Self {
        Self { minimum, maximum }
    }

    const fn matches(self, position: u8) -> bool {
        position >= self.minimum && position <= self.maximum
    }

    const fn is_valid(self) -> bool {
        self.minimum != 0 && self.maximum >= self.minimum
    }
}

/// Predicate applied to the incomplete token prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixPredicate<'descriptor> {
    /// Accept every prefix, including an empty prefix.
    Any,
    /// Accept prefixes beginning with the supplied text.
    StartsWith(&'descriptor str),
}

impl PrefixPredicate<'_> {
    fn matches(self, prefix: &str) -> bool {
        match self {
            Self::Any => true,
            Self::StartsWith(expected) => prefix.starts_with(expected),
        }
    }

    fn is_valid(self) -> bool {
        match self {
            Self::Any => true,
            Self::StartsWith(value) => valid_descriptor_text(value),
        }
    }
}

/// Predicate applied to an already parsed argument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArgumentCondition<'descriptor> {
    /// The zero-based previous argument must equal one value.
    Equals {
        /// Zero-based argument index after the command name.
        index: u8,
        /// Required exact value.
        value: &'descriptor str,
    },
    /// The zero-based previous argument must not equal one value.
    NotEquals {
        /// Zero-based argument index after the command name.
        index: u8,
        /// Rejected exact value.
        value: &'descriptor str,
    },
    /// The zero-based previous argument must begin with one value.
    StartsWith {
        /// Zero-based argument index after the command name.
        index: u8,
        /// Required prefix.
        value: &'descriptor str,
    },
    /// The zero-based previous argument must not begin with one value.
    NotStartsWith {
        /// Zero-based argument index after the command name.
        index: u8,
        /// Rejected prefix.
        value: &'descriptor str,
    },
}

impl<'descriptor> ArgumentCondition<'descriptor> {
    const fn index(self) -> u8 {
        match self {
            Self::Equals { index, .. }
            | Self::NotEquals { index, .. }
            | Self::StartsWith { index, .. }
            | Self::NotStartsWith { index, .. } => index,
        }
    }

    const fn value(self) -> &'descriptor str {
        match self {
            Self::Equals { value, .. }
            | Self::NotEquals { value, .. }
            | Self::StartsWith { value, .. }
            | Self::NotStartsWith { value, .. } => value,
        }
    }

    fn matches(self, arguments: &[Option<&str>]) -> bool {
        let actual = arguments.get(usize::from(self.index())).copied().flatten();
        match self {
            Self::Equals { value, .. } => actual == Some(value),
            Self::NotEquals { value, .. } => actual != Some(value),
            Self::StartsWith { value, .. } => actual.is_some_and(|item| item.starts_with(value)),
            Self::NotStartsWith { value, .. } => actual.is_none_or(|item| !item.starts_with(value)),
        }
    }
}

/// Filesystem entry kinds accepted by a trusted path resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathKind {
    /// Complete regular files only.
    File,
    /// Complete directories only.
    Directory,
    /// Complete either files or directories.
    Any,
}

/// Constraints supplied to a trusted filesystem resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathConstraints {
    kind: PathKind,
}

impl PathConstraints {
    /// Construct a path-domain request.
    #[must_use]
    pub const fn new(kind: PathKind) -> Self {
        Self { kind }
    }

    /// Requested filesystem entry kind.
    #[must_use]
    pub const fn kind(self) -> PathKind {
        self.kind
    }
}

/// Address families accepted by a trusted address resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    /// IPv4 addresses only.
    Ipv4,
    /// IPv6 addresses only.
    Ipv6,
    /// Either supported IP address family.
    Ip,
    /// Host names rather than numeric addresses.
    HostName,
    /// Numeric IP addresses or host names.
    Any,
}

/// Whether an address value carries a transport port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortRequirement {
    /// A port is not part of the value.
    Forbidden,
    /// A port may be present.
    Optional,
    /// A port must be present.
    Required,
}

/// Constraints supplied to a trusted address or endpoint resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressConstraints {
    family: AddressFamily,
    port: PortRequirement,
}

impl AddressConstraints {
    /// Construct an address-domain request.
    #[must_use]
    pub const fn new(family: AddressFamily, port: PortRequirement) -> Self {
        Self { family, port }
    }

    /// Accepted address family.
    #[must_use]
    pub const fn family(self) -> AddressFamily {
        self.family
    }

    /// Port syntax required by the value.
    #[must_use]
    pub const fn port(self) -> PortRequirement {
        self.port
    }
}

/// Radix accepted by a trusted integer resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegerRadix {
    /// Base-two representation.
    Binary,
    /// Base-eight representation.
    Octal,
    /// Base-ten representation.
    Decimal,
    /// Base-sixteen representation.
    Hexadecimal,
}

/// Constraints supplied to a trusted integer resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntegerConstraints {
    radix: IntegerRadix,
    minimum: Option<i64>,
    maximum: Option<i64>,
}

impl IntegerConstraints {
    /// Construct a possibly open-ended integer domain.
    #[must_use]
    pub const fn new(radix: IntegerRadix, minimum: Option<i64>, maximum: Option<i64>) -> Self {
        Self {
            radix,
            minimum,
            maximum,
        }
    }

    /// Accepted integer radix.
    #[must_use]
    pub const fn radix(self) -> IntegerRadix {
        self.radix
    }

    /// Inclusive lower bound, when configured.
    #[must_use]
    pub const fn minimum(self) -> Option<i64> {
        self.minimum
    }

    /// Inclusive upper bound, when configured.
    #[must_use]
    pub const fn maximum(self) -> Option<i64> {
        self.maximum
    }

    const fn is_valid(self) -> bool {
        match (self.minimum, self.maximum) {
            (Some(minimum), Some(maximum)) => minimum <= maximum,
            _ => true,
        }
    }
}

/// Semantic candidate domain selected by one descriptor rule.
///
/// The enum is intentionally closed. Its open-domain variants ask trusted
/// shell-side resolvers for current candidates; they are not finite value
/// lists and they do not grant the application authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resolver<'descriptor> {
    /// A descriptor-owned finite set of literal candidates.
    Values(&'descriptor [&'descriptor str]),
    /// Entries resolved relative to the shell's authoritative namespace.
    Path(PathConstraints),
    /// Names from the shell's authoritative command catalog.
    Command,
    /// Addresses or endpoints from an explicitly selected trusted source.
    Address(AddressConstraints),
    /// Integers satisfying the supplied typed bounds.
    Integer(IntegerConstraints),
    /// Jobs owned by the current shell session.
    Job,
    /// Services visible through the shell's supervisor view.
    Service,
    /// Configured volumes visible through the trusted mount-policy view.
    Volume,
}

/// One ordered declarative completion rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionRule<'descriptor> {
    position: ArgumentPosition,
    prefix: PrefixPredicate<'descriptor>,
    conditions: &'descriptor [ArgumentCondition<'descriptor>],
    resolver: Resolver<'descriptor>,
}

impl<'descriptor> CompletionRule<'descriptor> {
    /// Construct one rule evaluated in descriptor order.
    #[must_use]
    pub const fn new(
        position: ArgumentPosition,
        prefix: PrefixPredicate<'descriptor>,
        conditions: &'descriptor [ArgumentCondition<'descriptor>],
        resolver: Resolver<'descriptor>,
    ) -> Self {
        Self {
            position,
            prefix,
            conditions,
            resolver,
        }
    }

    fn matches(self, request: CompletionRequest<'_>) -> bool {
        self.position.matches(request.word_index)
            && self.prefix.matches(request.prefix)
            && self
                .conditions
                .iter()
                .all(|condition| condition.matches(request.arguments))
    }
}

/// Borrowed descriptor suitable for static recovery data or validated artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionDescriptor<'descriptor> {
    rules: &'descriptor [CompletionRule<'descriptor>],
}

impl<'descriptor> CompletionDescriptor<'descriptor> {
    /// Construct an unvalidated borrowed descriptor.
    #[must_use]
    pub const fn new(rules: &'descriptor [CompletionRule<'descriptor>]) -> Self {
        Self { rules }
    }

    /// Validate all descriptor structure and resource ceilings.
    ///
    /// # Errors
    ///
    /// Returns the first canonicality or capacity failure.
    pub fn validate(self) -> Result<ValidatedDescriptor<'descriptor>, DescriptorError> {
        if self.rules.len() > MAX_DESCRIPTOR_RULES {
            return Err(DescriptorError::TooManyRules);
        }
        for rule in self.rules {
            validate_rule(*rule)?;
        }
        Ok(ValidatedDescriptor { descriptor: self })
    }
}

/// Descriptor validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    /// The descriptor exceeds [`MAX_DESCRIPTOR_RULES`].
    TooManyRules,
    /// One rule exceeds [`MAX_RULE_CONDITIONS`].
    TooManyConditions,
    /// An argument-position range is empty or includes the command word.
    InvalidPosition,
    /// A condition addresses an argument outside the request policy.
    InvalidConditionIndex,
    /// A predicate or literal is empty, too long, or contains control text.
    InvalidText,
    /// A literal resolver contains no candidate values.
    EmptyValues,
    /// A literal resolver exceeds [`MAX_LITERAL_VALUES`].
    TooManyValues,
    /// A literal resolver exceeds [`MAX_LITERAL_BYTES`].
    LiteralBytesExceeded,
    /// An integer resolver's inclusive lower bound exceeds its upper bound.
    InvalidIntegerRange,
}

/// One fully validated completion descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedDescriptor<'descriptor> {
    descriptor: CompletionDescriptor<'descriptor>,
}

impl<'descriptor> ValidatedDescriptor<'descriptor> {
    /// Select the first matching semantic resolver.
    #[must_use]
    pub fn evaluate(
        self,
        request: CompletionRequest<'_>,
    ) -> Option<CompletionResolution<'descriptor>> {
        if request.limits.is_disabled() {
            return None;
        }
        self.descriptor
            .rules
            .iter()
            .copied()
            .find(|rule| rule.matches(request))
            .map(|rule| CompletionResolution {
                resolver: rule.resolver,
            })
    }
}

/// Validated parsed context supplied by the shell to a descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionRequest<'request> {
    word_index: u8,
    prefix: &'request str,
    arguments: &'request [Option<&'request str>],
    limits: CompletionLimits,
}

impl<'request> CompletionRequest<'request> {
    /// Validate one request for an application argument.
    ///
    /// `word_index` is one-based: one identifies the first argument after the
    /// command name. Missing entries in `arguments` represent parser context
    /// intentionally unavailable to declarative matching, such as quoted text.
    ///
    /// # Errors
    ///
    /// Rejects command-word positions, excessive arguments, or excessive
    /// retained request text.
    pub fn new(
        word_index: usize,
        prefix: &'request str,
        arguments: &'request [Option<&'request str>],
        limits: CompletionLimits,
    ) -> Result<Self, CompletionRequestError> {
        let word_index =
            u8::try_from(word_index).map_err(|_| CompletionRequestError::InvalidPosition)?;
        if word_index == 0 {
            return Err(CompletionRequestError::InvalidPosition);
        }
        if arguments.len() > MAX_REQUEST_ARGUMENTS {
            return Err(CompletionRequestError::TooManyArguments);
        }
        let mut retained_bytes = prefix.len();
        for argument in arguments.iter().flatten() {
            retained_bytes = retained_bytes
                .checked_add(argument.len())
                .ok_or(CompletionRequestError::TextBytesExceeded)?;
            if retained_bytes > MAX_REQUEST_TEXT_BYTES {
                return Err(CompletionRequestError::TextBytesExceeded);
            }
        }
        if retained_bytes > MAX_REQUEST_TEXT_BYTES {
            return Err(CompletionRequestError::TextBytesExceeded);
        }
        Ok(Self {
            word_index,
            prefix,
            arguments,
            limits,
        })
    }

    /// One-based argument position after the command name.
    #[must_use]
    pub const fn word_index(self) -> u8 {
        self.word_index
    }

    /// Incomplete token prefix ending at the shell cursor.
    #[must_use]
    pub const fn prefix(self) -> &'request str {
        self.prefix
    }

    /// Previously parsed argument context.
    #[must_use]
    pub const fn arguments(self) -> &'request [Option<&'request str>] {
        self.arguments
    }

    /// Shell-owned candidate budgets.
    #[must_use]
    pub const fn limits(self) -> CompletionLimits {
        self.limits
    }
}

/// Completion request validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionRequestError {
    /// Completion descriptors operate only on arguments after the command word.
    InvalidPosition,
    /// The request exceeds [`MAX_REQUEST_ARGUMENTS`].
    TooManyArguments,
    /// Referenced request text exceeds [`MAX_REQUEST_TEXT_BYTES`].
    TextBytesExceeded,
}

/// Semantic result selected by a validated declarative descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionResolution<'descriptor> {
    resolver: Resolver<'descriptor>,
}

impl<'descriptor> CompletionResolution<'descriptor> {
    /// Trusted semantic resolver selected for this request.
    #[must_use]
    pub const fn resolver(self) -> Resolver<'descriptor> {
        self.resolver
    }
}

fn validate_rule(rule: CompletionRule<'_>) -> Result<(), DescriptorError> {
    if !rule.position.is_valid() {
        return Err(DescriptorError::InvalidPosition);
    }
    if !rule.prefix.is_valid() {
        return Err(DescriptorError::InvalidText);
    }
    if rule.conditions.len() > MAX_RULE_CONDITIONS {
        return Err(DescriptorError::TooManyConditions);
    }
    for condition in rule.conditions {
        if usize::from(condition.index()) >= MAX_REQUEST_ARGUMENTS {
            return Err(DescriptorError::InvalidConditionIndex);
        }
        if !valid_descriptor_text(condition.value()) {
            return Err(DescriptorError::InvalidText);
        }
    }
    match rule.resolver {
        Resolver::Values(values) => validate_values(values),
        Resolver::Integer(constraints) if !constraints.is_valid() => {
            Err(DescriptorError::InvalidIntegerRange)
        }
        Resolver::Path(_)
        | Resolver::Command
        | Resolver::Address(_)
        | Resolver::Integer(_)
        | Resolver::Job
        | Resolver::Service
        | Resolver::Volume => Ok(()),
    }
}

fn validate_values(values: &[&str]) -> Result<(), DescriptorError> {
    if values.is_empty() {
        return Err(DescriptorError::EmptyValues);
    }
    if values.len() > MAX_LITERAL_VALUES {
        return Err(DescriptorError::TooManyValues);
    }
    let mut retained_bytes = 0_usize;
    for value in values {
        if !valid_descriptor_text(value) {
            return Err(DescriptorError::InvalidText);
        }
        retained_bytes = retained_bytes
            .checked_add(value.len())
            .ok_or(DescriptorError::LiteralBytesExceeded)?;
        if retained_bytes > MAX_LITERAL_BYTES {
            return Err(DescriptorError::LiteralBytesExceeded);
        }
    }
    Ok(())
}

fn valid_descriptor_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && !value.chars().any(char::is_control)
}

/// Canonical embedded completion-artifact rejection category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    /// The artifact exceeds [`MAX_ARTIFACT_BYTES`] or a descriptor ceiling.
    Capacity,
    /// The artifact header, line shape, token, or trailing newline is noncanonical.
    InvalidSyntax,
    /// The command identity is empty, excessive, or not a canonical command name.
    InvalidCommand,
    /// A rule contains an invalid position or condition index.
    InvalidPosition,
    /// A resolver name or typed constraint is unsupported or invalid.
    InvalidResolver,
    /// A literal or predicate is empty, excessive, duplicated, or noncanonical.
    InvalidText,
}

/// One parsed package-owned CMPL artifact.
///
/// CMPL v1 is canonical UTF-8 text so package authors can review the exact
/// bytes that are embedded in a KEX package. Fields are separated by tabs and
/// every record ends in `\n`:
///
/// `CMPL<TAB>1<TAB>command`
///
/// `R<TAB>min<TAB>max<TAB>*|^prefix<TAB>resolver[<TAB>condition...]`
///
/// Text operands are deliberately bare-word components: whitespace, control
/// bytes, `%`, `,`, `:`, and tabs are rejected. This matches the shell's
/// current insertion policy and leaves quoting extensions explicitly versioned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionArtifact {
    command: String,
    rules: Vec<OwnedRule>,
}

impl CompletionArtifact {
    /// Parse and validate one exact canonical CMPL v1 artifact.
    ///
    /// # Errors
    ///
    /// Rejects unknown syntax, noncanonical numbers, excessive resources,
    /// invalid typed constraints, and unsorted or duplicate literal values.
    pub fn parse(bytes: &[u8]) -> Result<Self, ArtifactError> {
        if bytes.len() > MAX_ARTIFACT_BYTES || !bytes.ends_with(b"\n") {
            return Err(if bytes.len() > MAX_ARTIFACT_BYTES {
                ArtifactError::Capacity
            } else {
                ArtifactError::InvalidSyntax
            });
        }
        let source = core::str::from_utf8(bytes).map_err(|_| ArtifactError::InvalidSyntax)?;
        if source.contains('\r') || source.contains("\n\n") {
            return Err(ArtifactError::InvalidSyntax);
        }
        let mut lines = source[..source.len() - 1].split('\n');
        let mut header = lines
            .next()
            .ok_or(ArtifactError::InvalidSyntax)?
            .split('\t');
        if header.next() != Some("CMPL")
            || header.next() != Some("1")
            || header.clone().count() != 1
        {
            return Err(ArtifactError::InvalidSyntax);
        }
        let command = header.next().ok_or(ArtifactError::InvalidSyntax)?;
        if !valid_command(command) {
            return Err(ArtifactError::InvalidCommand);
        }
        let mut rules = Vec::new();
        for line in lines {
            if rules.len() >= MAX_DESCRIPTOR_RULES {
                return Err(ArtifactError::Capacity);
            }
            rules.try_reserve(1).map_err(|_| ArtifactError::Capacity)?;
            rules.push(parse_artifact_rule(line)?);
        }
        Ok(Self {
            command: command.to_string(),
            rules,
        })
    }

    /// Exact command identity bound by this artifact.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Select the first matching semantic resolver.
    #[must_use]
    pub fn evaluate(&self, request: CompletionRequest<'_>) -> Option<ArtifactResolution<'_>> {
        if request.limits.is_disabled() {
            return None;
        }
        self.rules
            .iter()
            .find(|rule| rule.matches(request))
            .map(|rule| ArtifactResolution {
                resolver: rule.resolver.borrowed(),
            })
    }

    /// Number of validated ordered rules.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Semantic result borrowed from one parsed CMPL artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactResolution<'artifact> {
    resolver: ArtifactResolver<'artifact>,
}

impl<'artifact> ArtifactResolution<'artifact> {
    /// Trusted semantic resolver selected for this request.
    #[must_use]
    pub const fn resolver(self) -> ArtifactResolver<'artifact> {
        self.resolver
    }
}

/// Resolver selected from an owned parsed artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactResolver<'artifact> {
    /// A package-owned finite set of literal candidates.
    Values(&'artifact [String]),
    /// Entries from the shell's authoritative namespace.
    Path(PathConstraints),
    /// Names from the authoritative command catalog.
    Command,
    /// Addresses or endpoints satisfying typed constraints.
    Address(AddressConstraints),
    /// Integers satisfying typed constraints.
    Integer(IntegerConstraints),
    /// Jobs owned by the current shell session.
    Job,
    /// Services visible through the supervisor.
    Service,
    /// Volumes visible through configured mount policy.
    Volume,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnedRule {
    minimum: u8,
    maximum: u8,
    prefix: OwnedPrefix,
    conditions: Vec<OwnedCondition>,
    resolver: OwnedResolver,
}

impl OwnedRule {
    fn matches(&self, request: CompletionRequest<'_>) -> bool {
        request.word_index >= self.minimum
            && request.word_index <= self.maximum
            && self.prefix.matches(request.prefix)
            && self
                .conditions
                .iter()
                .all(|condition| condition.matches(request.arguments))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OwnedPrefix {
    Any,
    StartsWith(String),
}

impl OwnedPrefix {
    fn matches(&self, prefix: &str) -> bool {
        match self {
            Self::Any => true,
            Self::StartsWith(value) => prefix.starts_with(value),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OwnedCondition {
    Equals(u8, String),
    NotEquals(u8, String),
    StartsWith(u8, String),
    NotStartsWith(u8, String),
}

impl OwnedCondition {
    fn matches(&self, arguments: &[Option<&str>]) -> bool {
        let (index, expected) = match self {
            Self::Equals(index, value)
            | Self::NotEquals(index, value)
            | Self::StartsWith(index, value)
            | Self::NotStartsWith(index, value) => (*index, value.as_str()),
        };
        let actual = arguments.get(usize::from(index)).copied().flatten();
        match self {
            Self::Equals(_, _) => actual == Some(expected),
            Self::NotEquals(_, _) => actual != Some(expected),
            Self::StartsWith(_, _) => actual.is_some_and(|value| value.starts_with(expected)),
            Self::NotStartsWith(_, _) => actual.is_none_or(|value| !value.starts_with(expected)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OwnedResolver {
    Values(Vec<String>),
    Path(PathConstraints),
    Command,
    Address(AddressConstraints),
    Integer(IntegerConstraints),
    Job,
    Service,
    Volume,
}

impl OwnedResolver {
    const fn borrowed(&self) -> ArtifactResolver<'_> {
        match self {
            Self::Values(values) => ArtifactResolver::Values(values.as_slice()),
            Self::Path(value) => ArtifactResolver::Path(*value),
            Self::Command => ArtifactResolver::Command,
            Self::Address(value) => ArtifactResolver::Address(*value),
            Self::Integer(value) => ArtifactResolver::Integer(*value),
            Self::Job => ArtifactResolver::Job,
            Self::Service => ArtifactResolver::Service,
            Self::Volume => ArtifactResolver::Volume,
        }
    }
}

fn parse_artifact_rule(line: &str) -> Result<OwnedRule, ArtifactError> {
    let mut fields = line.split('\t');
    if fields.next() != Some("R") {
        return Err(ArtifactError::InvalidSyntax);
    }
    let minimum = parse_u8(fields.next().ok_or(ArtifactError::InvalidSyntax)?)?;
    let maximum_text = fields.next().ok_or(ArtifactError::InvalidSyntax)?;
    let maximum = if maximum_text == "*" {
        u8::MAX
    } else {
        parse_u8(maximum_text)?
    };
    if minimum == 0 || maximum < minimum {
        return Err(ArtifactError::InvalidPosition);
    }
    let prefix = match fields.next().ok_or(ArtifactError::InvalidSyntax)? {
        "*" => OwnedPrefix::Any,
        value if value.starts_with('^') && valid_token(&value[1..]) => {
            OwnedPrefix::StartsWith(value[1..].to_string())
        }
        _ => return Err(ArtifactError::InvalidText),
    };
    let resolver = parse_artifact_resolver(fields.next().ok_or(ArtifactError::InvalidSyntax)?)?;
    let mut conditions = Vec::new();
    for field in fields {
        if conditions.len() >= MAX_RULE_CONDITIONS {
            return Err(ArtifactError::Capacity);
        }
        conditions
            .try_reserve(1)
            .map_err(|_| ArtifactError::Capacity)?;
        conditions.push(parse_artifact_condition(field)?);
    }
    Ok(OwnedRule {
        minimum,
        maximum,
        prefix,
        conditions,
        resolver,
    })
}

fn parse_artifact_resolver(value: &str) -> Result<OwnedResolver, ArtifactError> {
    if value == "command" {
        return Ok(OwnedResolver::Command);
    }
    if value == "job" {
        return Ok(OwnedResolver::Job);
    }
    if value == "service" {
        return Ok(OwnedResolver::Service);
    }
    if value == "volume" {
        return Ok(OwnedResolver::Volume);
    }
    if let Some(kind) = value.strip_prefix("path:") {
        let kind = match kind {
            "file" => PathKind::File,
            "directory" => PathKind::Directory,
            "any" => PathKind::Any,
            _ => return Err(ArtifactError::InvalidResolver),
        };
        return Ok(OwnedResolver::Path(PathConstraints::new(kind)));
    }
    if let Some(values) = value.strip_prefix("values:") {
        let mut parsed = Vec::new();
        let mut retained_bytes = 0_usize;
        for candidate in values.split(',') {
            if parsed.len() >= MAX_LITERAL_VALUES || !valid_token(candidate) {
                return Err(ArtifactError::InvalidText);
            }
            if parsed
                .last()
                .is_some_and(|previous: &String| previous.as_str() >= candidate)
            {
                return Err(ArtifactError::InvalidText);
            }
            retained_bytes = retained_bytes
                .checked_add(candidate.len())
                .ok_or(ArtifactError::Capacity)?;
            if retained_bytes > MAX_LITERAL_BYTES {
                return Err(ArtifactError::Capacity);
            }
            parsed.try_reserve(1).map_err(|_| ArtifactError::Capacity)?;
            parsed.push(candidate.to_string());
        }
        if parsed.is_empty() {
            return Err(ArtifactError::InvalidText);
        }
        return Ok(OwnedResolver::Values(parsed));
    }
    if let Some(constraints) = value.strip_prefix("address:") {
        let mut fields = constraints.split(':');
        let family = match fields.next() {
            Some("ipv4") => AddressFamily::Ipv4,
            Some("ipv6") => AddressFamily::Ipv6,
            Some("ip") => AddressFamily::Ip,
            Some("hostname") => AddressFamily::HostName,
            Some("any") => AddressFamily::Any,
            _ => return Err(ArtifactError::InvalidResolver),
        };
        let port = match fields.next() {
            Some("forbidden") => PortRequirement::Forbidden,
            Some("optional") => PortRequirement::Optional,
            Some("required") => PortRequirement::Required,
            _ => return Err(ArtifactError::InvalidResolver),
        };
        if fields.next().is_some() {
            return Err(ArtifactError::InvalidResolver);
        }
        return Ok(OwnedResolver::Address(AddressConstraints::new(
            family, port,
        )));
    }
    if let Some(constraints) = value.strip_prefix("integer:") {
        let mut fields = constraints.split(':');
        let radix = match fields.next() {
            Some("binary") => IntegerRadix::Binary,
            Some("octal") => IntegerRadix::Octal,
            Some("decimal") => IntegerRadix::Decimal,
            Some("hexadecimal") => IntegerRadix::Hexadecimal,
            _ => return Err(ArtifactError::InvalidResolver),
        };
        let minimum = parse_optional_i64(fields.next().ok_or(ArtifactError::InvalidResolver)?)?;
        let maximum = parse_optional_i64(fields.next().ok_or(ArtifactError::InvalidResolver)?)?;
        if fields.next().is_some() || minimum.zip(maximum).is_some_and(|(low, high)| low > high) {
            return Err(ArtifactError::InvalidResolver);
        }
        return Ok(OwnedResolver::Integer(IntegerConstraints::new(
            radix, minimum, maximum,
        )));
    }
    Err(ArtifactError::InvalidResolver)
}

fn parse_artifact_condition(value: &str) -> Result<OwnedCondition, ArtifactError> {
    let mut fields = value.split(':');
    let operation = fields.next().ok_or(ArtifactError::InvalidSyntax)?;
    let index = parse_u8(fields.next().ok_or(ArtifactError::InvalidSyntax)?)?;
    if usize::from(index) >= MAX_REQUEST_ARGUMENTS {
        return Err(ArtifactError::InvalidPosition);
    }
    let expected = fields.next().ok_or(ArtifactError::InvalidSyntax)?;
    if fields.next().is_some() || !valid_token(expected) {
        return Err(ArtifactError::InvalidText);
    }
    let expected = expected.to_string();
    match operation {
        "eq" => Ok(OwnedCondition::Equals(index, expected)),
        "ne" => Ok(OwnedCondition::NotEquals(index, expected)),
        "starts" => Ok(OwnedCondition::StartsWith(index, expected)),
        "not-starts" => Ok(OwnedCondition::NotStartsWith(index, expected)),
        _ => Err(ArtifactError::InvalidSyntax),
    }
}

fn parse_u8(value: &str) -> Result<u8, ArtifactError> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(ArtifactError::InvalidSyntax);
    }
    value.parse().map_err(|_| ArtifactError::InvalidSyntax)
}

fn parse_optional_i64(value: &str) -> Result<Option<i64>, ArtifactError> {
    if value == "*" {
        return Ok(None);
    }
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.starts_with("-0")
        || value.starts_with('+')
    {
        return Err(ArtifactError::InvalidResolver);
    }
    value
        .parse()
        .map(Some)
        .map_err(|_| ArtifactError::InvalidResolver)
}

fn valid_command(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COMMAND_BYTES
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_graphic()
                && !matches!(
                    byte,
                    b'%' | b',' | b':' | b'\t' | b'\'' | b'"' | b'|' | b'&' | b'<' | b'>'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::{
        AddressConstraints, AddressFamily, ArgumentCondition, ArgumentPosition, ArtifactError,
        ArtifactResolver, CompletionArtifact, CompletionDescriptor, CompletionLimits,
        CompletionRequest, CompletionRequestError, CompletionRule, DescriptorError,
        IntegerConstraints, IntegerRadix, MAX_DESCRIPTOR_RULES, MAX_REQUEST_ARGUMENTS,
        PathConstraints, PathKind, PortRequirement, PrefixPredicate, Resolver,
    };

    const VALUES: &[&str] = &["listen", "send"];
    const SEND_CONDITION: &[ArgumentCondition<'_>] = &[ArgumentCondition::Equals {
        index: 0,
        value: "send",
    }];
    const RULES: &[CompletionRule<'_>] = &[
        CompletionRule::new(
            ArgumentPosition::exact(1),
            PrefixPredicate::Any,
            &[],
            Resolver::Values(VALUES),
        ),
        CompletionRule::new(
            ArgumentPosition::exact(2),
            PrefixPredicate::StartsWith("-"),
            SEND_CONDITION,
            Resolver::Integer(IntegerConstraints::new(
                IntegerRadix::Decimal,
                Some(1),
                Some(65_535),
            )),
        ),
    ];

    fn limits() -> CompletionLimits {
        CompletionLimits::new(64, 4096).unwrap_or_else(|_| std::process::abort())
    }

    #[test]
    fn ordered_rules_select_literal_and_open_domains() {
        let descriptor = CompletionDescriptor::new(RULES)
            .validate()
            .unwrap_or_else(|_| std::process::abort());
        let no_arguments = [None; 1];
        let first = CompletionRequest::new(1, "s", &no_arguments, limits())
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            descriptor
                .evaluate(first)
                .map(super::CompletionResolution::resolver),
            Some(Resolver::Values(VALUES))
        );

        let arguments = [Some("send")];
        let second = CompletionRequest::new(2, "-", &arguments, limits())
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            descriptor
                .evaluate(second)
                .map(super::CompletionResolution::resolver),
            Some(Resolver::Integer(IntegerConstraints::new(
                IntegerRadix::Decimal,
                Some(1),
                Some(65_535),
            )))
        );

        let listen = [Some("listen")];
        let unmatched = CompletionRequest::new(2, "-", &listen, limits())
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(descriptor.evaluate(unmatched), None);
    }

    #[test]
    fn open_domain_constraints_remain_typed() {
        let path = Resolver::Path(PathConstraints::new(PathKind::File));
        assert_eq!(path, Resolver::Path(PathConstraints::new(PathKind::File)));
        let endpoint = Resolver::Address(AddressConstraints::new(
            AddressFamily::Ipv4,
            PortRequirement::Required,
        ));
        assert_eq!(
            endpoint,
            Resolver::Address(AddressConstraints::new(
                AddressFamily::Ipv4,
                PortRequirement::Required,
            ))
        );
    }

    #[test]
    fn descriptor_validation_enforces_structure_and_integer_ranges() {
        let invalid_position = [CompletionRule::new(
            ArgumentPosition::exact(0),
            PrefixPredicate::Any,
            &[],
            Resolver::Command,
        )];
        assert_eq!(
            CompletionDescriptor::new(&invalid_position).validate(),
            Err(DescriptorError::InvalidPosition)
        );

        let invalid_integer = [CompletionRule::new(
            ArgumentPosition::exact(1),
            PrefixPredicate::Any,
            &[],
            Resolver::Integer(IntegerConstraints::new(
                IntegerRadix::Decimal,
                Some(2),
                Some(1),
            )),
        )];
        assert_eq!(
            CompletionDescriptor::new(&invalid_integer).validate(),
            Err(DescriptorError::InvalidIntegerRange)
        );

        let empty_values = [CompletionRule::new(
            ArgumentPosition::exact(1),
            PrefixPredicate::Any,
            &[],
            Resolver::Values(&[]),
        )];
        assert_eq!(
            CompletionDescriptor::new(&empty_values).validate(),
            Err(DescriptorError::EmptyValues)
        );

        let rule = CompletionRule::new(
            ArgumentPosition::exact(1),
            PrefixPredicate::Any,
            &[],
            Resolver::Service,
        );
        let too_many = [rule; MAX_DESCRIPTOR_RULES + 1];
        assert_eq!(
            CompletionDescriptor::new(&too_many).validate(),
            Err(DescriptorError::TooManyRules)
        );
    }

    #[test]
    fn request_validation_enforces_position_and_retained_argument_count() {
        assert_eq!(
            CompletionRequest::new(0, "", &[], limits()),
            Err(CompletionRequestError::InvalidPosition)
        );
        let too_many = [None; MAX_REQUEST_ARGUMENTS + 1];
        assert_eq!(
            CompletionRequest::new(1, "", &too_many, limits()),
            Err(CompletionRequestError::TooManyArguments)
        );
    }

    #[test]
    fn disabled_limits_suppress_a_valid_resolution() {
        let descriptor = CompletionDescriptor::new(RULES)
            .validate()
            .unwrap_or_else(|_| std::process::abort());
        let disabled = CompletionLimits::new(0, 0).unwrap_or_else(|_| std::process::abort());
        let request =
            CompletionRequest::new(1, "", &[], disabled).unwrap_or_else(|_| std::process::abort());
        assert_eq!(descriptor.evaluate(request), None);
    }

    #[test]
    fn canonical_artifact_binds_command_and_evaluates_owned_rules() {
        let bytes = b"CMPL\t1\tudp\nR\t1\t1\t*\tvalues:listen,send\nR\t2\t2\t*\tinteger:decimal:1:65535\teq:0:listen\n";
        let artifact = CompletionArtifact::parse(bytes).unwrap_or_else(|_| std::process::abort());
        assert_eq!(artifact.command(), "udp");
        assert_eq!(artifact.rule_count(), 2);
        let first =
            CompletionRequest::new(1, "s", &[], limits()).unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            artifact
                .evaluate(first)
                .map(super::ArtifactResolution::resolver),
            Some(ArtifactResolver::Values(&["listen".into(), "send".into()]))
        );
        let arguments = [Some("listen")];
        let second = CompletionRequest::new(2, "53", &arguments, limits())
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(
            artifact
                .evaluate(second)
                .map(super::ArtifactResolution::resolver),
            Some(ArtifactResolver::Integer(IntegerConstraints::new(
                IntegerRadix::Decimal,
                Some(1),
                Some(65_535),
            )))
        );
    }

    #[test]
    fn artifact_parser_rejects_noncanonical_or_unbound_text() {
        assert_eq!(
            CompletionArtifact::parse(b"CMPL\t1\tudp"),
            Err(ArtifactError::InvalidSyntax)
        );
        assert_eq!(
            CompletionArtifact::parse(b"CMPL\t1\tUDP\n"),
            Err(ArtifactError::InvalidCommand)
        );
        assert_eq!(
            CompletionArtifact::parse(b"CMPL\t1\tudp\nR\t1\t1\t*\tvalues:send,listen\n"),
            Err(ArtifactError::InvalidText)
        );
        assert_eq!(
            CompletionArtifact::parse(b"CMPL\t1\tudp\nR\t1\t1\t*\tvalues:send|reboot\n"),
            Err(ArtifactError::InvalidText)
        );
    }
}
