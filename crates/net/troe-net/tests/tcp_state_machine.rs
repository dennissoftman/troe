//! Adversarial transition tests for the bounded TCP connection machine.

use troe_net::{
    Ipv4Address, MAX_TCP_BACKLOG, MAX_TCP_RECEIVE_BYTES, NetError, TCP_TIME_WAIT_MILLISECONDS,
    TcpAdmission, TcpConnection, TcpEndpoint, TcpError, TcpFlags, TcpListener, TcpSegment,
    TcpState,
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

const SERVER: TcpEndpoint = match TcpEndpoint::new(Ipv4Address::new([10, 0, 2, 15]), 8080) {
    Ok(endpoint) => endpoint,
    Err(_) => panic!("valid server test endpoint"),
};
const CLIENT: TcpEndpoint = match TcpEndpoint::new(Ipv4Address::new([10, 0, 2, 2]), 49_152) {
    Ok(endpoint) => endpoint,
    Err(_) => panic!("valid client test endpoint"),
};
const SERVER_SEQUENCE: u32 = 0x2030_4050;
const CLIENT_SEQUENCE: u32 = 0x6070_8090;

fn client(port: u16) -> Result<TcpEndpoint, TcpError> {
    TcpEndpoint::new(Ipv4Address::new([10, 0, 2, 2]), port).map_err(|_| TcpError::Invalid)
}

/// Admit one client SYN and drain the answering SYN+ACK.
fn admit_syn(
    listener: &mut TcpListener,
    peer: TcpEndpoint,
    peer_sequence: u32,
    initial_sequence: u32,
) -> Result<(), TcpError> {
    assert_eq!(
        listener.on_segment(
            segment(peer, SERVER, peer_sequence, 0, TcpFlags::SYN, 4096, &[]),
            initial_sequence,
        ),
        TcpAdmission::Accepted
    );
    let syn_ack = listener.poll_emission(0).ok_or(TcpError::Invalid)?;
    assert_eq!(syn_ack.flags, TcpFlags::SYN_ACK);
    assert_eq!(syn_ack.sequence, initial_sequence);
    assert_eq!(syn_ack.acknowledgement, peer_sequence.wrapping_add(1));
    assert!(syn_ack.payload.is_empty());
    Ok(())
}

/// Complete one passive handshake and return the accepted server connection.
fn accepted() -> Result<TcpConnection, TcpError> {
    let mut listener = TcpListener::bind(SERVER, MAX_TCP_BACKLOG)?;
    admit_syn(&mut listener, CLIENT, CLIENT_SEQUENCE, SERVER_SEQUENCE)?;
    assert_eq!(
        listener.on_segment(
            segment(
                CLIENT,
                SERVER,
                CLIENT_SEQUENCE.wrapping_add(1),
                SERVER_SEQUENCE.wrapping_add(1),
                TcpFlags::ACK,
                4096,
                &[],
            ),
            SERVER_SEQUENCE,
        ),
        TcpAdmission::Accepted
    );
    let connection = listener.poll_accept().ok_or(TcpError::Invalid)?;
    assert_eq!(connection.state(), TcpState::Established);
    assert_eq!(listener.pending(), 0);
    Ok(connection)
}

#[test]
fn passive_open_completes_only_on_the_exact_final_acknowledgement() -> Result<(), TcpError> {
    let mut listener = TcpListener::bind(SERVER, MAX_TCP_BACKLOG)?;
    admit_syn(&mut listener, CLIENT, CLIENT_SEQUENCE, SERVER_SEQUENCE)?;

    // A future acknowledgement, a stale acknowledgement, an out-of-sequence
    // acknowledgement, and a segment without ACK all leave the half-open
    // connection unaccepted.
    for (sequence, acknowledgement, flags) in [
        (
            CLIENT_SEQUENCE.wrapping_add(1),
            SERVER_SEQUENCE.wrapping_add(2),
            TcpFlags::ACK,
        ),
        (
            CLIENT_SEQUENCE.wrapping_add(1),
            SERVER_SEQUENCE,
            TcpFlags::ACK,
        ),
        (
            CLIENT_SEQUENCE.wrapping_add(2),
            SERVER_SEQUENCE.wrapping_add(1),
            TcpFlags::ACK,
        ),
        (
            CLIENT_SEQUENCE.wrapping_add(1),
            SERVER_SEQUENCE.wrapping_add(1),
            TcpFlags::FIN,
        ),
    ] {
        assert_eq!(
            listener.on_segment(
                segment(CLIENT, SERVER, sequence, acknowledgement, flags, 4096, &[]),
                SERVER_SEQUENCE,
            ),
            TcpAdmission::Ignored
        );
        assert!(listener.poll_accept().is_none());
        assert_eq!(listener.pending(), 1);
    }

    assert_eq!(
        listener.on_segment(
            segment(
                CLIENT,
                SERVER,
                CLIENT_SEQUENCE.wrapping_add(1),
                SERVER_SEQUENCE.wrapping_add(1),
                TcpFlags::ACK,
                4096,
                &[],
            ),
            SERVER_SEQUENCE,
        ),
        TcpAdmission::Accepted
    );
    let connection = listener.poll_accept().ok_or(TcpError::Invalid)?;
    assert_eq!(connection.state(), TcpState::Established);
    assert_eq!(connection.buffered_bytes(), 0);
    Ok(())
}

#[test]
fn passive_open_retains_bytes_and_fin_carried_by_the_final_acknowledgement() -> Result<(), TcpError>
{
    let mut listener = TcpListener::bind(SERVER, MAX_TCP_BACKLOG)?;
    admit_syn(&mut listener, CLIENT, CLIENT_SEQUENCE, SERVER_SEQUENCE)?;

    // A client may pipeline its complete request onto the handshake's final
    // acknowledgement and close in the same segment.
    let request = b"GET / HTTP/1.1\r\n\r\n";
    assert_eq!(
        listener.on_segment(
            segment(
                CLIENT,
                SERVER,
                CLIENT_SEQUENCE.wrapping_add(1),
                SERVER_SEQUENCE.wrapping_add(1),
                TcpFlags::FIN_ACK,
                4096,
                request,
            ),
            SERVER_SEQUENCE,
        ),
        TcpAdmission::Accepted
    );
    let mut connection = listener.poll_accept().ok_or(TcpError::Invalid)?;
    assert_eq!(connection.state(), TcpState::CloseWait);
    assert_eq!(connection.buffered_bytes(), request.len());
    let mut received = [0_u8; 32];
    assert_eq!(
        connection.read(&mut received)?,
        Some(request.len()),
        "handshake-carried request bytes are retained"
    );
    assert_eq!(&received[..request.len()], request);
    assert_eq!(connection.read(&mut received)?, Some(0), "orderly peer EOF");
    // A peer may finish its request before the server writes the response.
    connection.begin_send(b"response")?;
    let _ack = connection.poll_emission(0)?;
    let response = connection.poll_emission(0)?.ok_or(TcpError::Invalid)?;
    assert_eq!(response.payload, b"response");
    Ok(())
}

#[test]
fn listener_admits_only_a_bare_syn_for_its_own_endpoint() -> Result<(), TcpError> {
    let mut listener = TcpListener::bind(SERVER, MAX_TCP_BACKLOG)?;
    let other_port =
        TcpEndpoint::new(Ipv4Address::new([10, 0, 2, 15]), 8081).map_err(|_| TcpError::Invalid)?;
    let other_address =
        TcpEndpoint::new(Ipv4Address::new([10, 0, 2, 99]), 8080).map_err(|_| TcpError::Invalid)?;

    // A different local port, a different local address, a SYN carrying data,
    // and a stray SYN+ACK never open a connection.
    for (destination, flags, payload) in [
        (other_port, TcpFlags::SYN, &b""[..]),
        (other_address, TcpFlags::SYN, &b""[..]),
        (SERVER, TcpFlags::SYN, &b"data"[..]),
        (SERVER, TcpFlags::SYN_ACK, &b""[..]),
        (SERVER, TcpFlags::ACK, &b""[..]),
        (SERVER, TcpFlags::FIN_ACK, &b""[..]),
        (SERVER, TcpFlags::RST, &b""[..]),
    ] {
        assert_eq!(
            listener.on_segment(
                segment(
                    CLIENT,
                    destination,
                    CLIENT_SEQUENCE,
                    0,
                    flags,
                    4096,
                    payload
                ),
                SERVER_SEQUENCE,
            ),
            TcpAdmission::Ignored
        );
        assert_eq!(listener.pending(), 0);
        assert!(listener.poll_emission(0).is_none());
    }
    Ok(())
}

#[test]
fn retransmitted_inbound_syn_never_opens_a_second_connection() -> Result<(), TcpError> {
    let mut listener = TcpListener::bind(SERVER, MAX_TCP_BACKLOG)?;
    admit_syn(&mut listener, CLIENT, CLIENT_SEQUENCE, SERVER_SEQUENCE)?;

    assert!(listener.has_connection(segment(
        CLIENT,
        SERVER,
        CLIENT_SEQUENCE,
        0,
        TcpFlags::SYN,
        4096,
        &[],
    )));
    assert!(!listener.has_connection(segment(
        SERVER,
        CLIENT,
        CLIENT_SEQUENCE,
        0,
        TcpFlags::SYN,
        4096,
        &[],
    )));

    // The pending SYN+ACK schedule answers a retransmitted SYN; a second
    // queue entry for the same tuple would duplicate the connection.
    assert_eq!(
        listener.on_segment(
            segment(CLIENT, SERVER, CLIENT_SEQUENCE, 0, TcpFlags::SYN, 4096, &[]),
            SERVER_SEQUENCE.wrapping_add(1),
        ),
        TcpAdmission::Duplicate
    );
    assert_eq!(listener.pending(), 1);

    // A SYN reusing the tuple with a different sequence is not the same open
    // and is refused rather than silently rebinding the connection.
    assert_eq!(
        listener.on_segment(
            segment(
                CLIENT,
                SERVER,
                CLIENT_SEQUENCE.wrapping_add(64),
                0,
                TcpFlags::SYN,
                4096,
                &[],
            ),
            SERVER_SEQUENCE.wrapping_add(1),
        ),
        TcpAdmission::Ignored
    );
    assert_eq!(listener.pending(), 1);
    Ok(())
}

#[test]
fn listener_backlog_is_bounded_and_drops_further_inbound_syns() -> Result<(), TcpError> {
    let mut listener = TcpListener::bind(SERVER, MAX_TCP_BACKLOG)?;
    assert_eq!(listener.capacity(), MAX_TCP_BACKLOG);
    for index in 0..MAX_TCP_BACKLOG {
        let port = 49_152_u16.saturating_add(u16::try_from(index).unwrap_or(u16::MAX));
        admit_syn(
            &mut listener,
            client(port)?,
            CLIENT_SEQUENCE,
            SERVER_SEQUENCE,
        )?;
    }
    assert_eq!(listener.pending(), MAX_TCP_BACKLOG);

    // The backlog is the containment boundary: an excess SYN is dropped, no
    // storage grows, and every retained connection is unaffected.
    let excess = client(49_152_u16.saturating_add(u16::try_from(MAX_TCP_BACKLOG).unwrap_or(0)))?;
    assert_eq!(
        listener.on_segment(
            segment(excess, SERVER, CLIENT_SEQUENCE, 0, TcpFlags::SYN, 4096, &[]),
            SERVER_SEQUENCE,
        ),
        TcpAdmission::Ignored
    );
    assert_eq!(listener.pending(), MAX_TCP_BACKLOG);

    // Accepting one connection reopens exactly one backlog slot.
    assert_eq!(
        listener.on_segment(
            segment(
                client(49_152)?,
                SERVER,
                CLIENT_SEQUENCE.wrapping_add(1),
                SERVER_SEQUENCE.wrapping_add(1),
                TcpFlags::ACK,
                4096,
                &[],
            ),
            SERVER_SEQUENCE,
        ),
        TcpAdmission::Accepted
    );
    let first = listener.poll_accept().ok_or(TcpError::Invalid)?;
    assert_eq!(first.state(), TcpState::Established);
    assert_eq!(listener.pending(), MAX_TCP_BACKLOG - 1);
    assert_eq!(
        listener.on_segment(
            segment(excess, SERVER, CLIENT_SEQUENCE, 0, TcpFlags::SYN, 4096, &[]),
            SERVER_SEQUENCE,
        ),
        TcpAdmission::Accepted
    );
    assert_eq!(listener.pending(), MAX_TCP_BACKLOG);
    Ok(())
}

#[test]
fn accept_never_returns_a_half_open_reset_or_timed_out_connection() -> Result<(), TcpError> {
    let mut listener = TcpListener::bind(SERVER, MAX_TCP_BACKLOG)?;
    admit_syn(&mut listener, CLIENT, CLIENT_SEQUENCE, SERVER_SEQUENCE)?;

    // A half-open connection is never handed to an application.
    assert!(listener.poll_accept().is_none());

    // An exact in-window reset terminates only that client's connection.
    assert_eq!(
        listener.on_segment(
            segment(
                CLIENT,
                SERVER,
                CLIENT_SEQUENCE.wrapping_add(1),
                0,
                TcpFlags::RST,
                4096,
                &[],
            ),
            SERVER_SEQUENCE,
        ),
        TcpAdmission::Accepted
    );
    assert_eq!(listener.pending(), 0);
    assert!(listener.poll_accept().is_none());

    // A silent client expires its own bounded SYN+ACK schedule and is
    // reclaimed without failing the listener.
    admit_syn(&mut listener, CLIENT, CLIENT_SEQUENCE, SERVER_SEQUENCE)?;
    for now in [250, 750, 1_750] {
        let retransmission = listener.poll_emission(now).ok_or(TcpError::Invalid)?;
        assert_eq!(retransmission.flags, TcpFlags::SYN_ACK);
    }
    assert!(
        listener.poll_emission(2_750).is_none(),
        "the fourth transmission's deadline ends the passive open"
    );
    assert!(listener.poll_accept().is_none());
    listener.reap();
    assert_eq!(listener.pending(), 0);
    Ok(())
}

#[test]
fn active_close_holds_the_tuple_in_time_wait_for_the_bounded_interval() -> Result<(), TcpError> {
    let mut connection = accepted()?;
    connection.begin_close()?;
    assert_eq!(connection.state(), TcpState::FinWaitOne);
    let fin = connection.poll_emission(0)?.ok_or(TcpError::Invalid)?;
    assert_eq!(fin.flags, TcpFlags::FIN_ACK);
    assert_eq!(fin.sequence, SERVER_SEQUENCE.wrapping_add(1));

    assert_eq!(
        connection.on_segment(segment(
            CLIENT,
            SERVER,
            CLIENT_SEQUENCE.wrapping_add(1),
            SERVER_SEQUENCE.wrapping_add(2),
            TcpFlags::ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.state(), TcpState::FinWaitTwo);
    assert_eq!(
        connection.on_segment(segment(
            CLIENT,
            SERVER,
            CLIENT_SEQUENCE.wrapping_add(1),
            SERVER_SEQUENCE.wrapping_add(2),
            TcpFlags::FIN_ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.state(), TcpState::TimeWait);

    // The interval starts at the first emission poll, which also drains the
    // final acknowledgement.
    let start = 10;
    let final_ack = connection.poll_emission(start)?.ok_or(TcpError::Invalid)?;
    assert_eq!(final_ack.flags, TcpFlags::ACK);
    assert_eq!(final_ack.acknowledgement, CLIENT_SEQUENCE.wrapping_add(2));

    // The tuple is retained, admits no further application operation, and
    // reports orderly end of stream.
    let expiry = start.saturating_add(TCP_TIME_WAIT_MILLISECONDS);
    assert!(connection.poll_emission(expiry - 1)?.is_none());
    assert_eq!(connection.state(), TcpState::TimeWait);
    assert!(!connection.is_closed(), "the tuple is not yet reclaimable");
    assert_eq!(connection.begin_send(b"late"), Err(TcpError::Closed));
    assert_eq!(connection.begin_close(), Err(TcpError::Closed));
    let mut received = [0_u8; 4];
    assert_eq!(connection.read(&mut received)?, Some(0));

    assert!(connection.poll_emission(expiry)?.is_none());
    assert_eq!(connection.state(), TcpState::Closed);
    assert!(connection.is_closed(), "the tuple is reclaimable at expiry");
    Ok(())
}

#[test]
fn simultaneous_close_enters_time_wait_through_closing() -> Result<(), TcpError> {
    let mut connection = accepted()?;
    connection.begin_close()?;
    let _fin = connection.poll_emission(0)?.ok_or(TcpError::Invalid)?;

    // The peer's FIN crosses our own before acknowledging it.
    assert_eq!(
        connection.on_segment(segment(
            CLIENT,
            SERVER,
            CLIENT_SEQUENCE.wrapping_add(1),
            SERVER_SEQUENCE.wrapping_add(1),
            TcpFlags::FIN_ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.state(), TcpState::Closing);

    assert_eq!(
        connection.on_segment(segment(
            CLIENT,
            SERVER,
            CLIENT_SEQUENCE.wrapping_add(2),
            SERVER_SEQUENCE.wrapping_add(2),
            TcpFlags::ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.state(), TcpState::TimeWait);
    assert_eq!(connection.begin_send(b"late"), Err(TcpError::Closed));
    Ok(())
}

#[test]
fn passive_close_reclaims_the_tuple_without_time_wait() -> Result<(), TcpError> {
    let mut connection = accepted()?;

    // The peer closes first, so this side is the passive closer and must not
    // retain the tuple after its own FIN is acknowledged.
    assert_eq!(
        connection.on_segment(segment(
            CLIENT,
            SERVER,
            CLIENT_SEQUENCE.wrapping_add(1),
            SERVER_SEQUENCE.wrapping_add(1),
            TcpFlags::FIN_ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.state(), TcpState::CloseWait);
    connection.begin_close()?;
    assert_eq!(connection.state(), TcpState::LastAck);
    let _ack = connection.poll_emission(0)?.ok_or(TcpError::Invalid)?;
    let fin = connection.poll_emission(0)?.ok_or(TcpError::Invalid)?;
    assert_eq!(fin.flags, TcpFlags::FIN_ACK);
    assert_eq!(
        connection.on_segment(segment(
            CLIENT,
            SERVER,
            CLIENT_SEQUENCE.wrapping_add(2),
            SERVER_SEQUENCE.wrapping_add(2),
            TcpFlags::ACK,
            4096,
            &[],
        ))?,
        TcpAdmission::Accepted
    );
    assert_eq!(connection.state(), TcpState::Closed);
    assert!(connection.is_closed());
    Ok(())
}

#[test]
fn listener_rejects_invalid_endpoints_and_capacities() {
    assert_eq!(
        TcpListener::bind(SERVER, 0).err(),
        Some(TcpError::Invalid),
        "a zero backlog would admit an open it cannot retain"
    );
    assert_eq!(
        TcpListener::bind(SERVER, MAX_TCP_BACKLOG + 1).err(),
        Some(TcpError::Invalid),
        "the backlog bound is part of the interface, not a hint"
    );
}
