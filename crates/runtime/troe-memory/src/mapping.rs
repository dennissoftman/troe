//! Virtual ranges and the single-address-space mapping plan.

use crate::{BASE_PAGE_SIZE, MAX_MAPPINGS, PhysicalRange};
use alloc::vec::Vec;
use core::fmt;

/// A checked, half-open, base-page-aligned virtual address range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VirtualRange {
    start: u64,
    end: u64,
}

impl VirtualRange {
    /// Construct a virtual range from a base address and page count.
    ///
    /// # Errors
    ///
    /// Rejects an unaligned start, zero pages, or checked arithmetic overflow.
    pub fn from_pages(start: u64, page_count: u64) -> Result<Self, MappingPlanError> {
        if !start.is_multiple_of(BASE_PAGE_SIZE) {
            return Err(MappingPlanError::Unaligned);
        }
        if page_count == 0 {
            return Err(MappingPlanError::Empty);
        }
        let byte_count = page_count
            .checked_mul(BASE_PAGE_SIZE)
            .ok_or(MappingPlanError::Overflow)?;
        let end = start
            .checked_add(byte_count)
            .ok_or(MappingPlanError::Overflow)?;
        Ok(Self { start, end })
    }

    /// First byte in the range.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// First byte after the range.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Number of bytes in the range.
    #[must_use]
    pub const fn byte_count(self) -> u64 {
        self.end - self.start
    }

    /// Number of base pages in the range.
    #[must_use]
    pub const fn page_count(self) -> u64 {
        self.byte_count() / BASE_PAGE_SIZE
    }
}

/// Access permissions for one virtual mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPermissions {
    /// Reads are permitted.
    pub read: bool,
    /// Writes are permitted.
    pub write: bool,
    /// Instruction fetches are permitted.
    pub execute: bool,
}

impl MappingPermissions {
    /// Read-only, non-executable memory.
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        execute: false,
    };
    /// Read/write, non-executable memory.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        execute: false,
    };
    /// Read/execute, immutable memory.
    pub const READ_EXECUTE: Self = Self {
        read: true,
        write: false,
        execute: true,
    };
}

/// Cache and ordering behavior required by a mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingMemoryType {
    /// Cacheable ordinary RAM or image memory.
    Normal,
    /// Strongly ordered, non-executable device registers.
    Device,
}

/// Component that owns the mapped bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingOwner {
    /// Immutable or executable bytes in the loaded kernel image.
    KernelImage,
    /// Runtime RAM owned by the kernel.
    KernelRuntime,
    /// Architecture-selected device registers.
    MachineDevice,
    /// Private pages retained by one isolated task address space.
    IsolatedTask,
}

/// Lifetime promised for a mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingLifetime {
    /// Required only while composing the owned machine.
    Boot,
    /// Required for the lifetime of the kernel address space.
    Kernel,
    /// Retained only until one isolated task is terminated and reaped.
    Task,
}

/// Least-privileged execution level allowed to traverse one mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPrivilege {
    /// Accessible only while executing in the kernel privilege level.
    Kernel,
    /// Accessible from the unprivileged task execution level.
    User,
}

/// One architecture-neutral virtual-to-physical mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mapping {
    virtual_range: VirtualRange,
    physical_range: PhysicalRange,
    permissions: MappingPermissions,
    memory_type: MappingMemoryType,
    owner: MappingOwner,
    lifetime: MappingLifetime,
    remappable: bool,
    privilege: MappingPrivilege,
}

impl Mapping {
    /// Construct a checked mapping record.
    ///
    /// # Errors
    ///
    /// Rejects unequal range lengths, unreadable mappings, writable executable
    /// mappings, and executable device memory.
    pub fn new(
        virtual_range: VirtualRange,
        physical_range: PhysicalRange,
        permissions: MappingPermissions,
        memory_type: MappingMemoryType,
        owner: MappingOwner,
        lifetime: MappingLifetime,
        remappable: bool,
    ) -> Result<Self, MappingPlanError> {
        if virtual_range.byte_count() != physical_range.byte_count() {
            return Err(MappingPlanError::LengthMismatch);
        }
        if !permissions.read {
            return Err(MappingPlanError::Unreadable);
        }
        if permissions.write && permissions.execute {
            return Err(MappingPlanError::WritableExecutable);
        }
        if memory_type == MappingMemoryType::Device && permissions.execute {
            return Err(MappingPlanError::ExecutableDevice);
        }
        Ok(Self {
            virtual_range,
            physical_range,
            permissions,
            memory_type,
            owner,
            lifetime,
            remappable,
            privilege: MappingPrivilege::Kernel,
        })
    }

    /// Construct a checked user-accessible mapping.
    ///
    /// Device memory cannot be exposed through this constructor. Stage 6 user
    /// tasks receive services through copied messages rather than ambient MMIO.
    ///
    /// # Errors
    ///
    /// Returns the ordinary mapping validation errors, or
    /// [`MappingPlanError::InvalidUserOwner`] for non-task ownership/lifetime.
    pub fn user(
        virtual_range: VirtualRange,
        physical_range: PhysicalRange,
        permissions: MappingPermissions,
        owner: MappingOwner,
        lifetime: MappingLifetime,
    ) -> Result<Self, MappingPlanError> {
        if owner != MappingOwner::IsolatedTask || lifetime != MappingLifetime::Task {
            return Err(MappingPlanError::InvalidUserOwner);
        }
        let mut mapping = Self::new(
            virtual_range,
            physical_range,
            permissions,
            MappingMemoryType::Normal,
            owner,
            lifetime,
            false,
        )?;
        mapping.privilege = MappingPrivilege::User;
        Ok(mapping)
    }

    /// Construct an identity mapping over one physical range.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::new`].
    pub fn identity(
        range: PhysicalRange,
        permissions: MappingPermissions,
        memory_type: MappingMemoryType,
        owner: MappingOwner,
        lifetime: MappingLifetime,
        remappable: bool,
    ) -> Result<Self, MappingPlanError> {
        let virtual_range = VirtualRange::from_pages(range.start(), range.page_count())?;
        Self::new(
            virtual_range,
            range,
            permissions,
            memory_type,
            owner,
            lifetime,
            remappable,
        )
    }

    /// Virtual range covered by this record.
    #[must_use]
    pub const fn virtual_range(self) -> VirtualRange {
        self.virtual_range
    }

    /// Physical range backing this record.
    #[must_use]
    pub const fn physical_range(self) -> PhysicalRange {
        self.physical_range
    }

    /// Access permissions enforced by the backend.
    #[must_use]
    pub const fn permissions(self) -> MappingPermissions {
        self.permissions
    }

    /// Cache and ordering classification.
    #[must_use]
    pub const fn memory_type(self) -> MappingMemoryType {
        self.memory_type
    }

    /// Mapping owner.
    #[must_use]
    pub const fn owner(self) -> MappingOwner {
        self.owner
    }

    /// Mapping lifetime.
    #[must_use]
    pub const fn lifetime(self) -> MappingLifetime {
        self.lifetime
    }

    /// Whether a later, explicitly authorized replacement may change it.
    #[must_use]
    pub const fn remappable(self) -> bool {
        self.remappable
    }

    /// Least-privileged execution level allowed to use the mapping.
    #[must_use]
    pub const fn privilege(self) -> MappingPrivilege {
        self.privilege
    }
}

/// Failures produced while constructing a virtual mapping plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPlanError {
    /// A range begins at an address that is not base-page aligned.
    Unaligned,
    /// A range contains no pages.
    Empty,
    /// Address or page-count arithmetic overflowed.
    Overflow,
    /// Virtual and physical ranges have different lengths.
    LengthMismatch,
    /// The requested access cannot be represented as a readable mapping.
    Unreadable,
    /// A mapping requested write and execute permission simultaneously.
    WritableExecutable,
    /// Device memory requested execute permission.
    ExecutableDevice,
    /// A user mapping did not carry isolated-task ownership and lifetime.
    InvalidUserOwner,
    /// Two virtual ranges overlap.
    VirtualOverlap,
    /// Two mappings refer to overlapping physical bytes.
    PhysicalOverlap,
    /// The explicit mapping-count bound was exceeded.
    TooManyMappings,
}

impl fmt::Display for MappingPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unaligned => formatter.write_str("mapping range is not page aligned"),
            Self::Empty => formatter.write_str("mapping range is empty"),
            Self::Overflow => formatter.write_str("mapping arithmetic overflowed"),
            Self::LengthMismatch => formatter.write_str("mapping range lengths differ"),
            Self::Unreadable => formatter.write_str("mapping is not readable"),
            Self::WritableExecutable => formatter.write_str("mapping is writable and executable"),
            Self::ExecutableDevice => formatter.write_str("device mapping is executable"),
            Self::InvalidUserOwner => {
                formatter.write_str("user mapping lacks isolated-task ownership")
            }
            Self::VirtualOverlap => formatter.write_str("virtual mappings overlap"),
            Self::PhysicalOverlap => formatter.write_str("physical mappings overlap"),
            Self::TooManyMappings => formatter.write_str("mapping plan bound exceeded"),
        }
    }
}

/// Sorted, virtually non-overlapping mappings for one address space.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MappingPlan {
    mappings: Vec<Mapping>,
}

impl MappingPlan {
    /// Construct an empty plan.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mappings: Vec::new(),
        }
    }

    /// Insert one mapping while preserving sorted, non-overlapping order.
    ///
    /// # Errors
    ///
    /// Rejects virtual overlap, unsafe physical aliases, and plans above
    /// [`MAX_MAPPINGS`]. Read-only aliases and RW/NX aliases are allowed; any
    /// physical alias that would combine write and execute permission is not.
    pub fn insert(&mut self, mapping: Mapping) -> Result<(), MappingPlanError> {
        if self.mappings.len() >= MAX_MAPPINGS {
            return Err(MappingPlanError::TooManyMappings);
        }
        let start = mapping.virtual_range.start;
        let index = self
            .mappings
            .partition_point(|existing| existing.virtual_range.start < start);
        if index > 0 && self.mappings[index - 1].virtual_range.end > start {
            return Err(MappingPlanError::VirtualOverlap);
        }
        if index < self.mappings.len()
            && mapping.virtual_range.end > self.mappings[index].virtual_range.start
        {
            return Err(MappingPlanError::VirtualOverlap);
        }
        for existing in &self.mappings {
            if ranges_overlap(existing.physical_range, mapping.physical_range)
                && !physical_alias_is_safe(*existing, mapping)
            {
                return Err(MappingPlanError::PhysicalOverlap);
            }
        }
        self.mappings
            .try_reserve(1)
            .map_err(|_| MappingPlanError::TooManyMappings)?;
        self.mappings.insert(index, mapping);
        Ok(())
    }

    /// Sorted mapping records.
    #[must_use]
    pub fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }

    /// Number of base pages described by the plan.
    ///
    /// # Errors
    ///
    /// Returns [`MappingPlanError::Overflow`] if the sum cannot be represented.
    pub fn page_count(&self) -> Result<u64, MappingPlanError> {
        self.mappings.iter().try_fold(0_u64, |total, mapping| {
            total
                .checked_add(mapping.virtual_range.page_count())
                .ok_or(MappingPlanError::Overflow)
        })
    }

    /// Whether the complete plan preserves W^X across virtual and physical aliases.
    #[must_use]
    pub fn enforces_global_w_xor_x(&self) -> bool {
        for (index, mapping) in self.mappings.iter().enumerate() {
            if mapping.permissions.write && mapping.permissions.execute {
                return false;
            }
            for other in &self.mappings[index + 1..] {
                if ranges_overlap(mapping.physical_range, other.physical_range)
                    && !physical_alias_is_safe(*mapping, *other)
                {
                    return false;
                }
            }
        }
        true
    }
}

fn physical_alias_is_safe(left: Mapping, right: Mapping) -> bool {
    if left.memory_type != right.memory_type {
        return false;
    }
    let writable = left.permissions.write || right.permissions.write;
    let executable = left.permissions.execute || right.permissions.execute;
    !(writable && executable)
}

const fn ranges_overlap(left: PhysicalRange, right: PhysicalRange) -> bool {
    left.start < right.end && right.start < left.end
}

#[cfg(test)]
mod tests {
    use crate::{
        BASE_PAGE_SIZE, Mapping, MappingLifetime, MappingMemoryType, MappingOwner,
        MappingPermissions, MappingPlan, MappingPlanError, MappingPrivilege, PhysicalRange,
        VirtualRange,
    };

    fn pages(start_page: u64, count: u64) -> PhysicalRange {
        let start = start_page * BASE_PAGE_SIZE;
        PhysicalRange {
            start,
            end: start + count * BASE_PAGE_SIZE,
        }
    }
    fn identity_mapping(
        start_page: u64,
        page_count: u64,
        permissions: MappingPermissions,
    ) -> Result<Mapping, MappingPlanError> {
        let range = PhysicalRange::from_pages(start_page * BASE_PAGE_SIZE, page_count)
            .map_err(|_| MappingPlanError::Overflow)?;
        Mapping::identity(
            range,
            permissions,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
            MappingLifetime::Kernel,
            false,
        )
    }

    #[test]
    fn mapping_plan_sorts_disjoint_ranges_and_counts_pages() -> Result<(), MappingPlanError> {
        let mut plan = MappingPlan::new();
        plan.insert(identity_mapping(8, 2, MappingPermissions::READ_WRITE)?)?;
        plan.insert(identity_mapping(2, 3, MappingPermissions::READ_EXECUTE)?)?;

        assert_eq!(
            plan.mappings()[0].virtual_range().start(),
            2 * BASE_PAGE_SIZE
        );
        assert_eq!(
            plan.mappings()[1].virtual_range().start(),
            8 * BASE_PAGE_SIZE
        );
        assert_eq!(plan.page_count(), Ok(5));
        assert!(plan.enforces_global_w_xor_x());
        Ok(())
    }

    #[test]
    fn mapping_plan_rejects_overlap_without_mutation() -> Result<(), MappingPlanError> {
        let mut plan = MappingPlan::new();
        plan.insert(identity_mapping(4, 4, MappingPermissions::READ_ONLY)?)?;
        assert_eq!(
            plan.insert(identity_mapping(6, 4, MappingPermissions::READ_WRITE)?),
            Err(MappingPlanError::VirtualOverlap)
        );
        assert_eq!(plan.mappings().len(), 1);
        Ok(())
    }

    fn aliased_mapping(
        virtual_page: u64,
        physical_page: u64,
        page_count: u64,
        permissions: MappingPermissions,
    ) -> Result<Mapping, MappingPlanError> {
        let virtual_range = VirtualRange::from_pages(virtual_page * BASE_PAGE_SIZE, page_count)?;
        let physical_range = PhysicalRange::from_pages(physical_page * BASE_PAGE_SIZE, page_count)
            .map_err(|_| MappingPlanError::Overflow)?;
        Mapping::new(
            virtual_range,
            physical_range,
            permissions,
            MappingMemoryType::Normal,
            MappingOwner::KernelRuntime,
            MappingLifetime::Kernel,
            false,
        )
    }

    #[test]
    fn mapping_plan_rejects_write_execute_aliases_in_both_orders() -> Result<(), MappingPlanError> {
        for (first, second) in [
            (
                MappingPermissions::READ_WRITE,
                MappingPermissions::READ_EXECUTE,
            ),
            (
                MappingPermissions::READ_EXECUTE,
                MappingPermissions::READ_WRITE,
            ),
        ] {
            let mut plan = MappingPlan::new();
            plan.insert(aliased_mapping(1, 8, 2, first)?)?;
            assert_eq!(
                plan.insert(aliased_mapping(20, 8, 2, second)?),
                Err(MappingPlanError::PhysicalOverlap)
            );
            assert_eq!(plan.mappings().len(), 1);
        }
        Ok(())
    }

    #[test]
    fn mapping_plan_accepts_only_aliases_that_preserve_global_w_xor_x()
    -> Result<(), MappingPlanError> {
        let mut plan = MappingPlan::new();
        plan.insert(aliased_mapping(1, 8, 4, MappingPermissions::READ_ONLY)?)?;
        plan.insert(aliased_mapping(20, 10, 4, MappingPermissions::READ_ONLY)?)?;
        plan.insert(aliased_mapping(30, 30, 2, MappingPermissions::READ_WRITE)?)?;
        plan.insert(aliased_mapping(50, 30, 2, MappingPermissions::READ_WRITE)?)?;
        assert!(plan.enforces_global_w_xor_x());

        let virtual_range = VirtualRange::from_pages(40 * BASE_PAGE_SIZE, 1)?;
        let physical_range = PhysicalRange::from_pages(8 * BASE_PAGE_SIZE, 1)
            .map_err(|_| MappingPlanError::Overflow)?;
        let user = Mapping::user(
            virtual_range,
            physical_range,
            MappingPermissions::READ_ONLY,
            MappingOwner::IsolatedTask,
            MappingLifetime::Task,
        )?;
        assert_eq!(user.privilege(), MappingPrivilege::User);
        plan.insert(user)?;
        assert!(plan.enforces_global_w_xor_x());
        Ok(())
    }

    #[test]
    fn mapping_plan_rejects_aliases_with_conflicting_memory_types() -> Result<(), MappingPlanError>
    {
        let mut plan = MappingPlan::new();
        plan.insert(aliased_mapping(1, 8, 1, MappingPermissions::READ_WRITE)?)?;
        let device = Mapping::new(
            VirtualRange::from_pages(20 * BASE_PAGE_SIZE, 1)?,
            pages(8, 1),
            MappingPermissions::READ_WRITE,
            MappingMemoryType::Device,
            MappingOwner::MachineDevice,
            MappingLifetime::Kernel,
            false,
        )?;
        assert_eq!(plan.insert(device), Err(MappingPlanError::PhysicalOverlap));
        assert_eq!(plan.mappings().len(), 1);
        Ok(())
    }

    #[test]
    fn user_mapping_requires_task_ownership_and_lifetime() -> Result<(), MappingPlanError> {
        let virtual_range = VirtualRange::from_pages(40 * BASE_PAGE_SIZE, 1)?;
        let physical_range = pages(8, 1);
        assert_eq!(
            Mapping::user(
                virtual_range,
                physical_range,
                MappingPermissions::READ_ONLY,
                MappingOwner::KernelRuntime,
                MappingLifetime::Task,
            ),
            Err(MappingPlanError::InvalidUserOwner)
        );
        assert_eq!(
            Mapping::user(
                virtual_range,
                physical_range,
                MappingPermissions::READ_ONLY,
                MappingOwner::IsolatedTask,
                MappingLifetime::Kernel,
            ),
            Err(MappingPlanError::InvalidUserOwner)
        );
        Ok(())
    }

    #[test]
    fn mapping_permissions_enforce_w_xor_x_and_device_nx() {
        let range = pages(1, 1);
        let writable_executable = MappingPermissions {
            read: true,
            write: true,
            execute: true,
        };
        assert_eq!(
            Mapping::identity(
                range,
                writable_executable,
                MappingMemoryType::Normal,
                MappingOwner::KernelImage,
                MappingLifetime::Kernel,
                false,
            ),
            Err(MappingPlanError::WritableExecutable)
        );
        assert_eq!(
            Mapping::identity(
                range,
                MappingPermissions::READ_EXECUTE,
                MappingMemoryType::Device,
                MappingOwner::MachineDevice,
                MappingLifetime::Kernel,
                false,
            ),
            Err(MappingPlanError::ExecutableDevice)
        );
    }

    #[test]
    fn mapping_range_arithmetic_and_lengths_are_checked() -> Result<(), MappingPlanError> {
        assert_eq!(
            VirtualRange::from_pages(1, 1),
            Err(MappingPlanError::Unaligned)
        );
        assert_eq!(VirtualRange::from_pages(0, 0), Err(MappingPlanError::Empty));
        assert_eq!(
            VirtualRange::from_pages(!(BASE_PAGE_SIZE - 1), 2),
            Err(MappingPlanError::Overflow)
        );
        let virtual_range = VirtualRange::from_pages(0, 2)?;
        assert_eq!(
            Mapping::new(
                virtual_range,
                pages(0, 1),
                MappingPermissions::READ_ONLY,
                MappingMemoryType::Normal,
                MappingOwner::KernelRuntime,
                MappingLifetime::Boot,
                true,
            ),
            Err(MappingPlanError::LengthMismatch)
        );
        Ok(())
    }
}
