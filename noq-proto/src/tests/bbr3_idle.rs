use super::*;

#[test]
fn bbr3_datagrams_recover_after_idle_keepalives() {
    // Sparse keepalives must stay app-limited so their delivery rate cannot
    // prematurely end STARTUP and collapse the window before application traffic.
    for idle_seconds in [0u64, 10, 30] {
        let mut bbr = crate::congestion::Bbr3Config::default();
        bbr.initial_window(512 * 1024);
        let mut cfg = TransportConfig::default();
        cfg.congestion_controller_factory(Arc::new(bbr));
        cfg.initial_mtu(1356).min_mtu(1356);
        cfg.datagram_send_buffer_size(4 * 1024 * 1024);
        cfg.datagram_send_codel(Some(crate::DatagramCodel {
            target: Duration::from_millis(5),
            interval: Duration::from_millis(100),
            max_delay: Some(Duration::from_millis(200)),
            scale_with_rtt: true,
        }));
        let mut pair = ConnPair::builder()
            .with_transport_cfg(cfg)
            .with_latency(Duration::from_millis(31))
            .enable_multipath()
            .disable_mtud_discovery()
            .connect();
        let mut received = 0;
        let mut sent = 0;
        // Send 400 datagrams/s for 12 seconds, then allow one second to drain.
        for tick in 0..((idle_seconds + 13) * 4000) {
            if tick % 4000 == 0 {
                pair.ping(Client);
                pair.ping(Server);
            }
            if tick >= idle_seconds * 4000 && tick < (idle_seconds + 12) * 4000 && tick % 10 == 0 {
                pair.datagrams(Client)
                    .send(Bytes::from(vec![0u8; 1206]), true)
                    .unwrap();
                sent += 1;
            }
            pair.drive_client();
            pair.drive_server();
            while let Some(data) = pair.datagrams(Server).recv() {
                pair.datagrams(Server).send(data, true).unwrap();
            }
            while pair.datagrams(Client).recv().is_some() {
                received += 1;
            }
            pair.time += Duration::from_micros(250);
        }
        assert_eq!(sent, 4800);
        assert!(
            received > sent * 9 / 10,
            "idle={idle_seconds} got {received}/{sent}"
        );
    }
}
