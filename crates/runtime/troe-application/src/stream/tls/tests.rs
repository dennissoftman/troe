use super::*;
use crate::{
    ABI_MINOR, KEX_V1_MIN_IMAGE_BASE, KEX_V1_USER_END, LoadPlacement, Target, encode_kex_package,
    parse_streamed_kex_package, parse_streamed_threaded_kex_package, stream_verified_segments,
    test_support::TlsFixture, tls_artifact::Artifact,
};
use alloc::{vec, vec::Vec};

fn read(bytes: &[u8]) -> impl FnMut(u64, &mut [u8]) -> Result<usize, ()> + '_ {
    move |offset, destination| {
        let source = bytes
            .get(usize::try_from(offset).map_err(|_| ())?..)
            .ok_or(())?;
        let count = source.len().min(destination.len()).min(137);
        destination[..count].copy_from_slice(&source[..count]);
        Ok(count)
    }
}
fn placement() -> LoadPlacement {
    LoadPlacement::new(KEX_V1_MIN_IMAGE_BASE, KEX_V1_USER_END - 4096)
}
fn package(bytes: &[u8]) -> Vec<u8> {
    encode_kex_package(bytes, &[]).unwrap_or_else(|_| unreachable!())
}

#[test]
fn threaded_stream_preserves_the_full_parser_contract_and_bounded_replay() {
    for target in [Target::X86_64, Target::Aarch64] {
        for file in [0, 3, 4097, 17000] {
            let bytes = TlsFixture {
                file,
                memory: file as u64 + 5001,
                ..TlsFixture::default()
            }
            .encode(target);
            let artifact = Artifact::parse(&bytes, target).unwrap_or_else(|_| unreachable!());
            let wrapped = package(&bytes);
            let plan = parse_streamed_threaded_kex_package(
                wrapped.len() as u64,
                read(&wrapped),
                target,
                placement(),
            )
            .unwrap_or_else(|e| unreachable!("{e:?}"));
            assert_eq!(plan.executable().tls_metadata(), Some(artifact.metadata()));
            let mut tls = vec![0xa5; file];
            stream_verified_tls(&plan, read(&wrapped), &mut tls).unwrap_or_else(|_| unreachable!());
            assert_eq!(tls, artifact.template());
            let mut image: Vec<_> = artifact
                .segments()
                .map(|s| vec![0xa5; s.file_bytes().len()])
                .collect();
            stream_verified_segments(&plan, read(&wrapped), |index, offset, bytes| {
                let offset = usize::try_from(offset).map_err(|_| ())?;
                image[index][offset..offset + bytes.len()].copy_from_slice(bytes);
                Ok(())
            })
            .unwrap_or_else(|_| unreachable!());
            for (actual, segment) in image.iter().zip(artifact.segments()) {
                assert_eq!(actual, segment.file_bytes());
            }
            for supported in [ABI_MINOR, u16::MAX] {
                assert!(
                    parse_streamed_kex_package(
                        wrapped.len() as u64,
                        read(&wrapped),
                        target,
                        supported,
                        placement()
                    )
                    .is_err()
                );
            }
        }
    }
}

#[test]
fn incoherent_tls_and_mutated_replay_are_rejected_before_publication() {
    let bytes = TlsFixture::default().encode(Target::X86_64);
    let wrapped = package(&bytes);
    let plan = parse_streamed_threaded_kex_package(
        wrapped.len() as u64,
        read(&wrapped),
        Target::X86_64,
        placement(),
    )
    .unwrap_or_else(|_| unreachable!());
    let mut changed = bytes.clone();
    *changed.last_mut().unwrap_or_else(|| unreachable!()) ^= 1;
    let changed = package(&changed);
    assert_eq!(
        parse_streamed_threaded_kex_package(
            changed.len() as u64,
            read(&changed),
            Target::X86_64,
            placement()
        )
        .err(),
        Some(StreamError::Tls(Error::InconsistentTemplate))
    );
    let mut destination = vec![
        0xa5;
        usize::try_from(
            plan.executable()
                .tls_metadata()
                .unwrap_or_else(|| unreachable!())
                .file_bytes
        )
        .unwrap_or_else(|_| unreachable!())
    ];
    assert_eq!(
        stream_verified_tls(&plan, read(&changed), &mut destination),
        Err(StreamError::SourceChanged)
    );
    destination.push(0xa5);
    let before = destination.clone();
    assert!(stream_verified_tls(&plan, read(&wrapped), &mut destination).is_err());
    assert_eq!(destination, before);
    assert_eq!(
        stream_verified_tls(&plan, |_, _| Ok(0), &mut destination[..before.len() - 1]),
        Err(StreamError::IncompleteRead)
    );
}

#[test]
fn resident_initializer_uses_stream_charges_and_encodes_the_managed_startup() {
    use crate::process_memory::{ProcessMemoryBudget, ProcessMemoryPlacement, ProcessMemoryPlan};
    use crate::tls_owner::{ProcessTls, TlsBackingAccount};
    use alloc::rc::Rc;
    use troe_abi::threading::{Kind, StartupReference, Token};
    let budget = ProcessMemoryBudget {
        mapped_pages: u64::MAX,
        resident_pages: u64::MAX,
        reserved_pages: u64::MAX,
        ordinary_frames: u64::MAX,
        ipc_pairs: 1,
        tls_pages: u64::MAX,
        template_pages: u64::MAX,
        staging_bytes: u64::MAX,
    };
    let placement = ProcessMemoryPlacement {
        image_base: KEX_V1_MIN_IMAGE_BASE,
        heap_capacity_pages: 16,
        initial_thread_base: KEX_V1_MIN_IMAGE_BASE + (1 << 24),
    };
    for target in [Target::X86_64, Target::Aarch64] {
        let bytes = TlsFixture {
            heap: 0,
            file: 17000,
            memory: 18000,
            ..TlsFixture::default()
        }
        .encode(target);
        let artifact = Artifact::parse(&bytes, target).unwrap_or_else(|_| unreachable!());
        let whole =
            ProcessMemoryPlan::new(&artifact, placement, budget).unwrap_or_else(|_| unreachable!());
        let wrapped = package(&bytes);
        let source = parse_streamed_threaded_kex_package(
            wrapped.len() as u64,
            read(&wrapped),
            target,
            LoadPlacement::new(placement.image_base, KEX_V1_USER_END - 4096),
        )
        .unwrap_or_else(|_| unreachable!());
        let account = Rc::new(TlsBackingAccount::new(4096));
        let process = ProcessTls::prepare_streamed(
            &source,
            placement,
            budget,
            Rc::clone(&account),
            read(&wrapped),
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            process.plan().regions().collect::<Vec<_>>(),
            whole.regions().collect::<Vec<_>>()
        );
        assert_eq!(
            process.plan().charges().staging_bytes(),
            crate::STREAM_WORKING_SET_BYTES as u64
        );
        assert_eq!(account.usage().staging_pages(), 0);
        assert_eq!(account.usage().pages(), process.backing_pages());
        let token = Token::new(Kind::Thread, 0, 1).unwrap_or_else(|_| unreachable!());
        let mut startup = [0xa5; PAGE_BYTES];
        process
            .plan()
            .encode_startup_page(
                token,
                crate::StartupInfo {
                    task_id: 1,
                    handles: &[],
                },
                &mut startup,
            )
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(&startup[6..8], &4_u16.to_le_bytes());
        assert_eq!(
            StartupReference::decode(&startup[80..96])
                .unwrap_or_else(|_| unreachable!())
                .address,
            process.plan().initial_thread().regions()[3].start()
        );
        let mut changed = wrapped.clone();
        changed[0] ^= 1;
        let baseline = account.usage();
        assert!(
            ProcessTls::prepare_streamed(
                &source,
                placement,
                budget,
                Rc::clone(&account),
                read(&changed)
            )
            .is_err()
        );
        assert_eq!(account.usage(), baseline);
        drop(process);
        assert_eq!(account.usage().pages(), 0);
    }
}

#[test]
fn streamed_tls_rejects_bss_entries_executable_sources_and_relocated_initializers() {
    use crate::bytes::{read_u32, read_u64, write_u32, write_u64};
    for target in [Target::X86_64, Target::Aarch64] {
        let original = TlsFixture::default().encode(target);
        let mut invalid = Vec::new();
        for offset in [24, 136] {
            let mut bytes = original.clone();
            write_u64(&mut bytes, offset, 4092);
            invalid.push(bytes);
        }
        let mut executable_source = original.clone();
        write_u64(&mut executable_source, 96, 0);
        invalid.push(executable_source);
        let mut relocated = original.clone();
        let payload = usize::try_from(read_u32(&relocated, 60).unwrap_or_else(|_| unreachable!()))
            .unwrap_or_else(|_| unreachable!());
        let source = read_u64(&relocated, 96).unwrap_or_else(|_| unreachable!());
        let mut record = [0; 16];
        write_u64(&mut record, 0, source);
        relocated.splice(payload..payload, record);
        write_u32(
            &mut relocated,
            60,
            u32::try_from(payload + 16).unwrap_or_else(|_| unreachable!()),
        );
        write_u32(&mut relocated, 68, 1);
        let length = relocated.len() as u64;
        write_u64(&mut relocated, 80, length);
        for offset in [104, 168, 208] {
            let old = read_u64(&relocated, offset).unwrap_or_else(|_| unreachable!());
            write_u64(&mut relocated, offset, old + 16);
        }
        invalid.push(relocated);
        for bytes in invalid {
            assert!(Artifact::parse(&bytes, target).is_err());
            let wrapped = package(&bytes);
            assert!(
                parse_streamed_threaded_kex_package(
                    wrapped.len() as u64,
                    read(&wrapped),
                    target,
                    placement()
                )
                .is_err()
            );
        }
    }
}
