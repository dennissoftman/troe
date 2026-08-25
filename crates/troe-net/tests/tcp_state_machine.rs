//! Adversarial transition tests for the bounded TCP connection machine.

use troe_net::{
    Ipv4Address, MAX_TCP_RECEIVE_BYTES, NetError, TcpAdmission, TcpConnection, TcpEndpoint,
    TcpError, TcpFlags, TcpSegment, TcpState,
};

const LOCAL: TcpEndpoint = match TcpEndpoint::new(Ipv4Address::new([10, 0, 2, 15]), 49_152) {
    Ok(endpoint) => endpoint,
    Err(_) => panic!("valid local test endpoint"),
};
const REMOTE: TcpEndpoint = match TcpEndpoint::new(Ipv4Address::new([10, 0, 2, 2]), 8080) {
    Ok(endpoint) => endpoint,
    Err(_) => panic!("valid remote test endpoint"),
};
const LOCAL_SEQUENCE: u32 = 0x1020_3040;
const REMOTE_SEQUENCE: u32 = 0x5060_7080;

fn segment(
    source: TcpEndpoint,
    destination: TcpEndpoint,
    sequence: u32,
    acknowledgement: u32,
    flags: TcpFlags,
    window: u16,
    payload: &[u8],
) -> TcpSegment<'_> {
    TcpSegment {
        source,
        destination,
        sequence,
        acknowledgement,
        flags,
        window,
        payload,
    }
}

fn established() -> Result<TcpConnection, TcpError> {
    let mut connection = TcpConnection::connect(LOCAL, REMOTE, LOCAL_SEQUENCE)?;
    let syn = connection.poll_emission(0)?.ok_or(TcpError::Invalid)?;
    assert_eq!(syn.sequence, LOCAL_SEQUENCE);
    assert_eq!(syn.flags, TcpFlags::SYN);
    assert!(syn.payload.is_empty());
    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            REMOTE_SEQUENCE,
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::SYN_ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    let ack = connection.poll_emission(1)?.ok_or(TcpError::Invalid)?;
    assert_eq!(ack.flags, TcpFlags::ACK);
    assert_eq!(ack.sequence, LOCAL_SEQUENCE.wrapping_add(1));
    assert_eq!(ack.acknowledgement, REMOTE_SEQUENCE.wrapping_add(1));
    assert_eq!(connection.state(), TcpState::Established);
    Ok(connection)
}

#[test]
fn handshake_rejects_wrong_tuple_ack_and_flag_combinations() -> Result<(), TcpError> {
    let mut connection = TcpConnection::connect(LOCAL, REMOTE, LOCAL_SEQUENCE)?;
    let _syn = connection.poll_emission(0)?.ok_or(TcpError::Invalid)?;

    let wrong_peer =
        TcpEndpoint::new(Ipv4Address::new([10, 0, 2, 99]), 8080).map_err(|_| TcpError::Invalid)?;
    assert_eq!(
        connection.on_segment(segment(
            wrong_peer,
            LOCAL,
            REMOTE_SEQUENCE,
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::SYN_ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Ignored
    );
    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            REMOTE_SEQUENCE,
            LOCAL_SEQUENCE,
            TcpFlags::SYN_ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Ignored
    );
    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            REMOTE_SEQUENCE,
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Ignored
    );
    assert_eq!(connection.state(), TcpState::SynSent);

    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            REMOTE_SEQUENCE,
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::SYN_ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.state(), TcpState::Established);
    Ok(())
}

#[test]
fn out_of_order_duplicate_and_over_window_data_are_never_redelivered() -> Result<(), TcpError> {
    let mut connection = established()?;
    let expected = REMOTE_SEQUENCE.wrapping_add(1);

    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            expected.wrapping_add(3),
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::ACK,
            4096,
            b"future",
        ))?,
        TcpAdmission::Ignored
    );
    assert_eq!(connection.buffered_bytes(), 0);

    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            expected,
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::ACK,
            4096,
            b"once",
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            expected,
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::ACK,
            4096,
            b"once",
        ))?,
        TcpAdmission::Duplicate
    );
    assert_eq!(connection.buffered_bytes(), 4);

    let mut sequence = expected.wrapping_add(4);
    let block = [0x5a_u8; 1024];
    for _ in 0..3 {
        assert_eq!(
            connection.on_segment(segment(
                REMOTE,
                LOCAL,
                sequence,
                LOCAL_SEQUENCE.wrapping_add(1),
                TcpFlags::ACK,
                4096,
                &block,
            ))?,
            TcpAdmission::Accepted
        );
        sequence = sequence.wrapping_add(1024);
    }
    let tail = [0xa5_u8; MAX_TCP_RECEIVE_BYTES - 4 - 3 * 1024];
    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            sequence,
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::ACK,
            4096,
            &tail,
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.buffered_bytes(), MAX_TCP_RECEIVE_BYTES);
    assert_eq!(connection.advertised_window(), 0);

    let before = connection.buffered_bytes();
    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            sequence.wrapping_add(u32::try_from(tail.len()).map_err(|_| TcpError::Invalid)?),
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::ACK,
            4096,
            b"overflow",
        ))?,
        TcpAdmission::Ignored
    );
    assert_eq!(connection.buffered_bytes(), before);

    let mut received = [0_u8; MAX_TCP_RECEIVE_BYTES];
    assert_eq!(connection.read(&mut received)?, Some(MAX_TCP_RECEIVE_BYTES));
    assert_eq!(&received[..4], b"once");
    assert_eq!(connection.read(&mut received)?, None);
    Ok(())
}

#[test]
fn future_and_partial_acks_cannot_complete_a_write() -> Result<(), TcpError> {
    let mut connection = established()?;
    connection.begin_send(b"bounded")?;
    let emission = connection.poll_emission(10)?.ok_or(TcpError::Invalid)?;
    let data_sequence = emission.sequence;
    assert_eq!(emission.flags, TcpFlags::PSH_ACK);
    assert_eq!(emission.payload, b"bounded");

    for (acknowledgement, admission) in [
        (data_sequence, TcpAdmission::Accepted),
        (data_sequence.wrapping_add(1), TcpAdmission::Ignored),
        (data_sequence.wrapping_add(8), TcpAdmission::Ignored),
    ] {
        assert_eq!(
            connection.on_segment(segment(
                REMOTE,
                LOCAL,
                REMOTE_SEQUENCE.wrapping_add(1),
                acknowledgement,
                TcpFlags::ACK,
                4096,
                &[],
            ))?,
            admission
        );
        assert!(!connection.send_complete()?);
    }

    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            REMOTE_SEQUENCE.wrapping_add(1),
            data_sequence.wrapping_add(7),
            TcpFlags::ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert!(connection.send_complete()?);
    Ok(())
}

#[test]
fn retransmission_attempts_and_timeout_are_hard_bounded() -> Result<(), TcpError> {
    let mut connection = TcpConnection::connect(LOCAL, REMOTE, LOCAL_SEQUENCE)?;
    for (now, expected_attempt) in [(0, 1), (250, 2), (750, 3), (1750, 4)] {
        let emission = connection.poll_emission(now)?.ok_or(TcpError::Invalid)?;
        assert_eq!(emission.sequence, LOCAL_SEQUENCE);
        assert_eq!(emission.flags, TcpFlags::SYN);
        assert_eq!(connection.transmit_attempts(), expected_attempt);
        assert!(connection.poll_emission(now)?.is_none());
    }
    assert_eq!(connection.poll_emission(2750), Err(TcpError::Timeout));
    assert_eq!(connection.state(), TcpState::Closed);
    assert!(connection.poll_emission(u64::MAX)?.is_none());
    Ok(())
}

#[test]
fn reset_must_be_in_window_and_close_preserves_buffered_bytes() -> Result<(), TcpError> {
    let mut connection = established()?;
    let receive_sequence = REMOTE_SEQUENCE.wrapping_add(1);

    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            receive_sequence.wrapping_add(1),
            0,
            TcpFlags::RST,
            0,
            &[],
        ))?,
        TcpAdmission::Ignored
    );
    assert_eq!(connection.state(), TcpState::Established);

    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            receive_sequence,
            LOCAL_SEQUENCE.wrapping_add(1),
            TcpFlags::FIN_ACK,
            4096,
            b"last",
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.state(), TcpState::CloseWait);
    let mut bytes = [0_u8; 8];
    assert_eq!(connection.read(&mut bytes)?, Some(4));
    assert_eq!(&bytes[..4], b"last");
    assert_eq!(connection.read(&mut bytes)?, Some(0));
    let window_update = connection.poll_emission(1)?.ok_or(TcpError::Invalid)?;
    assert_eq!(window_update.flags, TcpFlags::ACK);

    connection.begin_close()?;
    let fin = connection.poll_emission(2)?.ok_or(TcpError::Invalid)?;
    assert_eq!(fin.flags, TcpFlags::FIN_ACK);
    let fin_sequence = fin.sequence;
    assert_eq!(connection.state(), TcpState::LastAck);
    assert_eq!(
        connection.on_segment(segment(
            REMOTE,
            LOCAL,
            receive_sequence.wrapping_add(5),
            fin_sequence.wrapping_add(1),
            TcpFlags::ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.state(), TcpState::Closed);
    Ok(())
}

#[test]
fn exact_in_window_reset_is_terminal_and_sequence_wrap_is_defined() -> Result<(), TcpError> {
    let mut wrapped = TcpConnection::connect(LOCAL, REMOTE, u32::MAX)?;
    let syn = wrapped.poll_emission(0)?.ok_or(TcpError::Invalid)?;
    assert_eq!(syn.sequence, u32::MAX);
    assert_eq!(
        wrapped.on_segment(segment(
            REMOTE,
            LOCAL,
            u32::MAX,
            0,
            TcpFlags::SYN_ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(wrapped.state(), TcpState::Established);
    assert_eq!(
        wrapped.on_segment(segment(REMOTE, LOCAL, 0, 0, TcpFlags::RST, 0, &[],)),
        Err(TcpError::Reset)
    );
    assert_eq!(wrapped.state(), TcpState::Closed);
    assert_eq!(wrapped.read(&mut [0_u8; 1]), Err(TcpError::Reset));
    Ok(())
}

#[test]
fn endpoints_reject_zero_ports() {
    assert_eq!(
        TcpEndpoint::new(Ipv4Address::new([192, 0, 2, 1]), 0),
        Err(NetError::Invalid)
    );
}
