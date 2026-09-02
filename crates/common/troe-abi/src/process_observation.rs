//! Capability-scoped observation of foreground, background, and service processes.

use core::str;

/// Interface major version.
pub const MAJOR: u16 = 1;
/// Interface minor version.
pub const MINOR: u16 = 1;
/// Read one current bounded process snapshot.
pub const GET_SNAPSHOT: u16 = 1;
/// Read one stable-ID-cursor page of current process records.
pub const GET_PAGE: u16 = 2;
/// Maximum observable live processes.
pub const MAX_PROCESSES: usize = 16;
/// Maximum UTF-8 bytes in one executable name.
pub const MAX_NAME_BYTES: usize = 32;
/// Fixed snapshot-header bytes.
pub const HEADER_BYTES: usize = 32;
/// Fixed process-record bytes.
pub const RECORD_BYTES: usize = 112;
/// Exact canonical snapshot bytes.
pub const SNAPSHOT_BYTES: usize = HEADER_BYTES + MAX_PROCESSES * RECORD_BYTES;
/// Maximum process records returned by one paginated call.
pub const MAX_PAGE_PROCESSES: usize = 32;
/// Fixed paginated-response header bytes.
pub const PAGE_HEADER_BYTES: usize = 48;
/// Exact canonical paginated-response bytes.
pub const PAGE_BYTES: usize = PAGE_HEADER_BYTES + MAX_PAGE_PROCESSES * RECORD_BYTES;
/// Exact stable-ID cursor request bytes.
pub const PAGE_REQUEST_BYTES: usize = 8;

const MAGIC: [u8; 8] = *b"PROCv1\0\0";
const PAGE_MAGIC: [u8; 8] = *b"PROCpg1\0";

/// Observable launcher placement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Origin {
    /// Shell foreground terminal owner.
    Foreground = 1,
    /// Session-owned background job.
    Background = 2,
    /// Supervised service.
    Service = 3,
    /// Owner-scoped nested child.
    Child = 4,
}

/// Observable process lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum State {
    /// Eligible for execution.
    Ready = 1,
    /// Currently executing unprivileged code.
    Running = 2,
    /// Waiting for one typed completion.
    Blocked = 3,
    /// Cancellation requested; teardown pending.
    Stopping = 4,
}

/// Fixed-capacity UTF-8 executable name without arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessName {
    bytes: [u8; MAX_NAME_BYTES],
    len: u8,
}

impl ProcessName {
    /// Copy one nonempty bounded UTF-8 name.
    ///
    /// # Errors
    ///
    /// Rejects empty names and names above [`MAX_NAME_BYTES`].
    pub fn new(name: &str) -> Result<Self, EncodingError> {
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return Err(EncodingError);
        }
        let mut bytes = [0_u8; MAX_NAME_BYTES];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self {
            bytes,
            len: u8::try_from(name.len()).map_err(|_| EncodingError)?,
        })
    }

    /// Borrow the validated UTF-8 name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or("invalid-process-name")
    }
}

/// One immutable process observation record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Process {
    /// Monotonic non-reused process identity.
    pub id: u64,
    /// Internal monotonic scheduler task identity.
    pub task_id: u64,
    /// Boot-relative process launch time.
    pub started_millis: u64,
    /// High-resolution ticks spent within user execution boundaries.
    pub cpu_ticks: u64,
    /// Total retained application pages.
    pub resident_pages: u64,
    /// Retained page-table pages.
    pub table_pages: u64,
    /// Retained private image, startup, heap, and stack pages.
    pub private_pages: u64,
    /// Scheduler dispatch selections.
    pub dispatches: u32,
    /// Voluntary yields.
    pub yields: u32,
    /// Timer-driven resumable preemptions.
    pub preemptions: u32,
    /// Live generation-checked handles.
    pub handles: u16,
    /// Current lifecycle state.
    pub state: State,
    /// Launcher placement.
    pub origin: Origin,
    /// Executable name without arguments.
    pub name: ProcessName,
}

const EMPTY_NAME: ProcessName = ProcessName {
    bytes: [0; MAX_NAME_BYTES],
    len: 0,
};
const EMPTY_PROCESS: Process = Process {
    id: 0,
    task_id: 0,
    started_millis: 0,
    cpu_ticks: 0,
    resident_pages: 0,
    table_pages: 0,
    private_pages: 0,
    dispatches: 0,
    yields: 0,
    preemptions: 0,
    handles: 0,
    state: State::Ready,
    origin: Origin::Foreground,
    name: EMPTY_NAME,
};

/// One exact bounded current-process snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    observed_millis: u64,
    counter_frequency_hz: u64,
    processes: [Process; MAX_PROCESSES],
    count: usize,
}

/// One fixed-size page from a stable-ID-cursor process scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Page {
    observed_millis: u64,
    counter_frequency_hz: u64,
    next_cursor: u64,
    total_processes: u32,
    processes: [Process; MAX_PAGE_PROCESSES],
    count: usize,
}

impl Page {
    /// Construct one canonical process page.
    ///
    /// # Errors
    ///
    /// Rejects invalid frequency, cursor, counts, ordering, or records.
    pub fn new(
        observed_millis: u64,
        counter_frequency_hz: u64,
        next_cursor: u64,
        total_processes: u32,
        processes: &[Process],
    ) -> Result<Self, EncodingError> {
        if counter_frequency_hz == 0
            || processes.len() > MAX_PAGE_PROCESSES
            || usize::try_from(total_processes).map_err(|_| EncodingError)? < processes.len()
            || (processes.is_empty() && next_cursor != 0)
            || (next_cursor != 0 && processes.last().map(|process| process.id) != Some(next_cursor))
        {
            return Err(EncodingError);
        }
        let mut retained = [EMPTY_PROCESS; MAX_PAGE_PROCESSES];
        let mut previous = 0_u64;
        for (destination, process) in retained.iter_mut().zip(processes.iter().copied()) {
            validate_process(process)?;
            if process.id <= previous {
                return Err(EncodingError);
            }
            previous = process.id;
            *destination = process;
        }
        Ok(Self {
            observed_millis,
            counter_frequency_hz,
            next_cursor,
            total_processes,
            processes: retained,
            count: processes.len(),
        })
    }

    /// Boot-relative observation time.
    #[must_use]
    pub const fn observed_millis(self) -> u64 {
        self.observed_millis
    }

    /// Counter frequency used by every record.
    #[must_use]
    pub const fn counter_frequency_hz(self) -> u64 {
        self.counter_frequency_hz
    }

    /// Last returned process ID, or zero when this scan is complete.
    #[must_use]
    pub const fn next_cursor(self) -> u64 {
        self.next_cursor
    }

    /// Number of live records when this page was observed.
    #[must_use]
    pub const fn total_processes(self) -> u32 {
        self.total_processes
    }

    /// Records in ascending process-ID order.
    #[must_use]
    pub fn processes(&self) -> &[Process] {
        &self.processes[..self.count]
    }
}

impl Snapshot {
    /// Construct one snapshot by copying current records.
    ///
    /// # Errors
    ///
    /// Rejects zero frequency, excess records, or inconsistent records.
    pub fn new(
        observed_millis: u64,
        counter_frequency_hz: u64,
        processes: &[Process],
    ) -> Result<Self, EncodingError> {
        if counter_frequency_hz == 0 || processes.len() > MAX_PROCESSES {
            return Err(EncodingError);
        }
        let mut retained = [EMPTY_PROCESS; MAX_PROCESSES];
        for (destination, process) in retained.iter_mut().zip(processes.iter().copied()) {
            validate_process(process)?;
            *destination = process;
        }
        Ok(Self {
            observed_millis,
            counter_frequency_hz,
            processes: retained,
            count: processes.len(),
        })
    }

    /// Boot-relative time at which the snapshot was encoded.
    #[must_use]
    pub const fn observed_millis(self) -> u64 {
        self.observed_millis
    }

    /// Frequency used to convert `cpu_ticks` into time.
    #[must_use]
    pub const fn counter_frequency_hz(self) -> u64 {
        self.counter_frequency_hz
    }

    /// Current records in stable registration order.
    #[must_use]
    pub fn processes(&self) -> &[Process] {
        &self.processes[..self.count]
    }
}

/// Invalid, inconsistent, or noncanonical process snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncodingError;

/// Encode one exact canonical fixed-size snapshot.
///
/// # Errors
///
/// Rejects inconsistent record values or bounds.
pub fn encode_snapshot(snapshot: Snapshot) -> Result<[u8; SNAPSHOT_BYTES], EncodingError> {
    if snapshot.counter_frequency_hz == 0 || snapshot.count > MAX_PROCESSES {
        return Err(EncodingError);
    }
    let mut bytes = [0_u8; SNAPSHOT_BYTES];
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..10].copy_from_slice(
        &u16::try_from(snapshot.count)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    bytes[10..12].copy_from_slice(
        &u16::try_from(RECORD_BYTES)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    bytes[12..16].copy_from_slice(
        &u32::try_from(SNAPSHOT_BYTES)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    write_u64(&mut bytes, 16, snapshot.observed_millis);
    write_u64(&mut bytes, 24, snapshot.counter_frequency_hz);
    for (index, process) in snapshot.processes().iter().copied().enumerate() {
        let at = HEADER_BYTES + index * RECORD_BYTES;
        encode_process(&mut bytes[at..at + RECORD_BYTES], process)?;
    }
    Ok(bytes)
}

/// Decode one exact canonical fixed-size snapshot.
///
/// # Errors
///
/// Rejects malformed, noncanonical, truncated, or inconsistent bytes.
pub fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot, EncodingError> {
    if bytes.len() != SNAPSHOT_BYTES
        || bytes[..8] != MAGIC
        || usize::from(read_u16(bytes, 10)?) != RECORD_BYTES
        || usize::try_from(read_u32(bytes, 12)?).map_err(|_| EncodingError)? != SNAPSHOT_BYTES
    {
        return Err(EncodingError);
    }
    let count = usize::from(read_u16(bytes, 8)?);
    if count > MAX_PROCESSES || read_u64(bytes, 24)? == 0 {
        return Err(EncodingError);
    }
    let mut processes = [EMPTY_PROCESS; MAX_PROCESSES];
    for (index, destination) in processes.iter_mut().take(count).enumerate() {
        let at = HEADER_BYTES + index * RECORD_BYTES;
        *destination = decode_process(&bytes[at..at + RECORD_BYTES])?;
    }
    let used = HEADER_BYTES + count * RECORD_BYTES;
    if bytes[used..].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    Snapshot::new(
        read_u64(bytes, 16)?,
        read_u64(bytes, 24)?,
        &processes[..count],
    )
}

/// Encode one stable-ID cursor request.
#[must_use]
pub const fn encode_page_request(after_process_id: u64) -> [u8; PAGE_REQUEST_BYTES] {
    after_process_id.to_le_bytes()
}

/// Decode one stable-ID cursor request.
///
/// # Errors
///
/// Rejects every non-exact request.
pub fn decode_page_request(bytes: &[u8]) -> Result<u64, EncodingError> {
    if bytes.len() != PAGE_REQUEST_BYTES {
        return Err(EncodingError);
    }
    read_u64(bytes, 0)
}

/// Encode one exact fixed-size process page.
///
/// # Errors
///
/// Rejects inconsistent page metadata or records.
pub fn encode_page(page: Page) -> Result<[u8; PAGE_BYTES], EncodingError> {
    let canonical = Page::new(
        page.observed_millis,
        page.counter_frequency_hz,
        page.next_cursor,
        page.total_processes,
        page.processes(),
    )?;
    let mut bytes = [0_u8; PAGE_BYTES];
    bytes[..8].copy_from_slice(&PAGE_MAGIC);
    bytes[8..10].copy_from_slice(
        &u16::try_from(canonical.count)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    bytes[10..12].copy_from_slice(
        &u16::try_from(RECORD_BYTES)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    bytes[12..16].copy_from_slice(
        &u32::try_from(PAGE_BYTES)
            .map_err(|_| EncodingError)?
            .to_le_bytes(),
    );
    write_u64(&mut bytes, 16, canonical.observed_millis);
    write_u64(&mut bytes, 24, canonical.counter_frequency_hz);
    write_u64(&mut bytes, 32, canonical.next_cursor);
    bytes[40..44].copy_from_slice(&canonical.total_processes.to_le_bytes());
    for (index, process) in canonical.processes().iter().copied().enumerate() {
        let at = PAGE_HEADER_BYTES + index * RECORD_BYTES;
        encode_process(&mut bytes[at..at + RECORD_BYTES], process)?;
    }
    Ok(bytes)
}

/// Decode one exact fixed-size process page.
///
/// # Errors
///
/// Rejects malformed, noncanonical, truncated, or inconsistent bytes.
pub fn decode_page(bytes: &[u8]) -> Result<Page, EncodingError> {
    if bytes.len() != PAGE_BYTES
        || bytes[..8] != PAGE_MAGIC
        || usize::from(read_u16(bytes, 10)?) != RECORD_BYTES
        || usize::try_from(read_u32(bytes, 12)?).map_err(|_| EncodingError)? != PAGE_BYTES
        || bytes[44..PAGE_HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(EncodingError);
    }
    let count = usize::from(read_u16(bytes, 8)?);
    if count > MAX_PAGE_PROCESSES || read_u64(bytes, 24)? == 0 {
        return Err(EncodingError);
    }
    let mut processes = [EMPTY_PROCESS; MAX_PAGE_PROCESSES];
    for (index, destination) in processes.iter_mut().take(count).enumerate() {
        let at = PAGE_HEADER_BYTES + index * RECORD_BYTES;
        *destination = decode_process(&bytes[at..at + RECORD_BYTES])?;
    }
    let used = PAGE_HEADER_BYTES + count * RECORD_BYTES;
    if bytes[used..].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    Page::new(
        read_u64(bytes, 16)?,
        read_u64(bytes, 24)?,
        read_u64(bytes, 32)?,
        read_u32(bytes, 40)?,
        &processes[..count],
    )
}

fn encode_process(bytes: &mut [u8], process: Process) -> Result<(), EncodingError> {
    if bytes.len() != RECORD_BYTES {
        return Err(EncodingError);
    }
    validate_process(process)?;
    write_u64(bytes, 0, process.id);
    write_u64(bytes, 8, process.task_id);
    write_u64(bytes, 16, process.started_millis);
    write_u64(bytes, 24, process.cpu_ticks);
    write_u64(bytes, 32, process.resident_pages);
    write_u64(bytes, 40, process.table_pages);
    write_u64(bytes, 48, process.private_pages);
    write_u32(bytes, 56, process.dispatches);
    write_u32(bytes, 60, process.yields);
    write_u32(bytes, 64, process.preemptions);
    bytes[68..70].copy_from_slice(&process.handles.to_le_bytes());
    bytes[70] = process.state as u8;
    bytes[71] = process.origin as u8;
    bytes[72] = process.name.len;
    bytes[80..112].copy_from_slice(&process.name.bytes);
    Ok(())
}

fn decode_process(bytes: &[u8]) -> Result<Process, EncodingError> {
    if bytes.len() != RECORD_BYTES || bytes[73..80].iter().any(|byte| *byte != 0) {
        return Err(EncodingError);
    }
    let name_len = usize::from(bytes[72]);
    if name_len == 0
        || name_len > MAX_NAME_BYTES
        || bytes[80 + name_len..112].iter().any(|byte| *byte != 0)
    {
        return Err(EncodingError);
    }
    let name = str::from_utf8(&bytes[80..80 + name_len]).map_err(|_| EncodingError)?;
    let process = Process {
        id: read_u64(bytes, 0)?,
        task_id: read_u64(bytes, 8)?,
        started_millis: read_u64(bytes, 16)?,
        cpu_ticks: read_u64(bytes, 24)?,
        resident_pages: read_u64(bytes, 32)?,
        table_pages: read_u64(bytes, 40)?,
        private_pages: read_u64(bytes, 48)?,
        dispatches: read_u32(bytes, 56)?,
        yields: read_u32(bytes, 60)?,
        preemptions: read_u32(bytes, 64)?,
        handles: read_u16(bytes, 68)?,
        state: match bytes[70] {
            1 => State::Ready,
            2 => State::Running,
            3 => State::Blocked,
            4 => State::Stopping,
            _ => return Err(EncodingError),
        },
        origin: match bytes[71] {
            1 => Origin::Foreground,
            2 => Origin::Background,
            3 => Origin::Service,
            4 => Origin::Child,
            _ => return Err(EncodingError),
        },
        name: ProcessName::new(name)?,
    };
    validate_process(process)?;
    Ok(process)
}

fn validate_process(process: Process) -> Result<(), EncodingError> {
    if process.id == 0
        || process.task_id == 0
        || process.table_pages == 0
        || process.private_pages == 0
        || process.resident_pages != process.table_pages.saturating_add(process.private_pages)
        || process.name.as_str().is_empty()
    {
        return Err(EncodingError);
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, EncodingError> {
    let value = bytes.get(offset..offset + 2).ok_or(EncodingError)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, EncodingError> {
    let value = bytes.get(offset..offset + 4).ok_or(EncodingError)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, EncodingError> {
    let value = bytes.get(offset..offset + 8).ok_or(EncodingError)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use crate::process_observation;

    #[test]
    fn process_snapshot_is_fixed_bounded_and_hides_arguments() {
        let process = process_observation::Process {
            id: 42,
            task_id: 7,
            started_millis: 100,
            cpu_ticks: 12_000,
            resident_pages: 21,
            table_pages: 9,
            private_pages: 12,
            dispatches: 4,
            yields: 1,
            preemptions: 2,
            handles: 6,
            state: process_observation::State::Running,
            origin: process_observation::Origin::Foreground,
            name: process_observation::ProcessName::new("top")
                .unwrap_or_else(|_| std::process::abort()),
        };
        let snapshot = process_observation::Snapshot::new(200, 1_000_000, &[process])
            .unwrap_or_else(|_| std::process::abort());
        let bytes = process_observation::encode_snapshot(snapshot)
            .unwrap_or_else(|_| std::process::abort());
        assert_eq!(bytes.len(), process_observation::SNAPSHOT_BYTES);
        let decoded =
            process_observation::decode_snapshot(&bytes).unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.observed_millis(), 200);
        assert_eq!(decoded.counter_frequency_hz(), 1_000_000);
        assert_eq!(decoded.processes(), &[process]);
        assert_eq!(decoded.processes()[0].name.as_str(), "top");

        let mut invalid_tail = bytes;
        invalid_tail[process_observation::SNAPSHOT_BYTES - 1] = 1;
        assert!(process_observation::decode_snapshot(&invalid_tail).is_err());
        let mut invalid_state = bytes;
        invalid_state[process_observation::HEADER_BYTES + 70] = 0;
        assert!(process_observation::decode_snapshot(&invalid_state).is_err());
        assert!(process_observation::ProcessName::new("").is_err());
        assert!(
            process_observation::ProcessName::new("123456789012345678901234567890123").is_err()
        );

        let page = process_observation::Page::new(200, 1_000_000, 42, 65_536, &[process])
            .unwrap_or_else(|_| std::process::abort());
        let page_bytes =
            process_observation::encode_page(page).unwrap_or_else(|_| std::process::abort());
        let decoded =
            process_observation::decode_page(&page_bytes).unwrap_or_else(|_| std::process::abort());
        assert_eq!(decoded.next_cursor(), 42);
        assert_eq!(decoded.total_processes(), 65_536);
        assert_eq!(decoded.processes(), &[process]);
        assert_eq!(
            process_observation::decode_page_request(&process_observation::encode_page_request(
                u64::MAX
            )),
            Ok(u64::MAX)
        );
    }
}
