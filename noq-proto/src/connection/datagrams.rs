use alloc::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::Connection;
use crate::{
    DatagramCodel, Duration, FrameStats, Instant, TransportError,
    connection::PacketBuilder,
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if data.len() > Ord::min(max, send_buffer_size) {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            self.conn
                .datagrams
                .make_space_for(data.len(), send_buffer_size);
        } else if !self
            .conn
            .datagrams
            .has_send_buffer_space(data.len(), send_buffer_size)
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.push_outgoing(data);
        Ok(())
    }

    /// Queue many unreliable, unordered datagrams for transmission in a single call.
    ///
    /// This is the batch analogue of [`Self::send`], avoiding repeated connection checks.
    ///
    /// The batch is rejected atomically with the [`TooLarge`] error if any datagram
    /// in the batch is too large.
    ///
    /// `drop` selects the backpressure behaviour, matching [`Self::send`]:
    ///
    /// - `drop = true` drops the oldest queued datagrams to make room, so every element is queued
    ///   and `Ok(datagrams.len())` is returned.
    /// - `drop = false` queues elements until the send buffer is full, then stops and returns
    ///   `Ok(n)` for the `n` elements queued. The remaining elements are the caller's to retry once
    ///   space frees up.
    ///
    /// Returns `Err` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// [`TooLarge`]: SendDatagramError::TooLarge
    pub fn send_many(
        &mut self,
        datagrams: &[Bytes],
        drop: bool,
    ) -> Result<usize, SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        if datagrams
            .iter()
            .any(|data| data.len() > Ord::min(max, send_buffer_size))
        {
            return Err(SendDatagramError::TooLarge);
        }

        let mut queued = 0usize;
        for data in datagrams {
            if drop {
                self.conn
                    .datagrams
                    .make_space_for(data.len(), send_buffer_size);
            } else if !self
                .conn
                .datagrams
                .has_send_buffer_space(data.len(), send_buffer_size)
            {
                self.conn.datagrams.send_blocked = true;
                break;
            }
            self.conn.datagrams.push_outgoing(data.clone());
            queued += 1;
        }

        Ok(queued)
    }

    /// Compute the maximum size of datagrams that may be passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// When multipath is enabled, this is calculated using the smallest MTU across all
    /// available paths.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.current_mtu() as usize
            - self.conn.predict_1rtt_overhead_no_pn()
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Drain up to `out.len()` buffered datagrams into `out`, in arrival order.
    ///
    /// This is the batch analogue of [`Self::recv`]: a single call takes many
    /// datagrams at once. `out` is filled from the front and overwritten in place;
    /// pass a slice of empty `Bytes` sized to the batch you want. Returns the number
    /// of datagrams written, which may be less than `out.len()` if fewer are buffered
    /// (0 if none). Any remaining datagrams stay queued for the next call.
    pub fn recv_many(&mut self, out: &mut [Bytes]) -> usize {
        self.conn.datagrams.recv_many(out)
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing_total)
    }
}

#[derive(Default)]
pub(super) struct DatagramState {
    /// Number of bytes of datagrams that have been received by the local transport but not
    /// delivered to the application
    pub(super) recv_buffered: usize,
    pub(super) incoming: VecDeque<Datagram>,
    pub(super) outgoing: VecDeque<OutgoingDatagram>,
    pub(super) outgoing_total: usize,
    pub(super) send_blocked: bool,
    /// Queue management state, see [`TransportConfig::datagram_send_codel`].
    ///
    /// [`TransportConfig::datagram_send_codel`]: crate::TransportConfig::datagram_send_codel
    codel: Codel,
    /// Outgoing datagrams dropped by queue management.
    pub(super) dropped_delay: u64,
    /// Outgoing datagrams dropped for space in the send buffer or for exceeding the MTU.
    pub(super) dropped_overflow: u64,
}

/// An outgoing datagram waiting in the send buffer
pub(super) struct OutgoingDatagram {
    pub(super) datagram: Datagram,
    /// When the datagram was queued, if known yet
    ///
    /// `Datagrams::send` has no notion of time, so datagrams are stamped by the next
    /// [`DatagramState::manage_queue`], which runs whenever the connection polls for transmits.
    queued: Option<Instant>,
}

/// CoDel state (RFC 8289, section 5)
#[derive(Debug, Default)]
struct Codel {
    /// When the queueing delay will have stayed above the target for an interval
    first_above_time: Option<Instant>,
    /// When to drop next while in the dropping state
    drop_next: Option<Instant>,
    /// Drops since entering the dropping state
    count: u32,
    /// `count` when the dropping state was last entered
    last_count: u32,
    dropping: bool,
}

impl Codel {
    /// Whether the head datagram may be dropped, tracking how long the delay has been high
    fn ok_to_drop(
        &mut self,
        sojourn: Duration,
        queued_bytes: usize,
        max_datagram: usize,
        now: Instant,
        config: DatagramCodel,
    ) -> bool {
        // A queue of at most one packet's worth is not a standing queue.
        if sojourn < config.target || queued_bytes <= max_datagram {
            self.first_above_time = None;
            return false;
        }
        match self.first_above_time {
            None => {
                self.first_above_time = Some(now + config.interval);
                false
            }
            Some(t) => now >= t,
        }
    }
}

/// When to drop next: the drop rate grows with the square root of the drop count.
fn control_law(t: Instant, interval: Duration, count: u32) -> Instant {
    t + interval.div_f64(f64::from(count.max(1)).sqrt())
}

impl DatagramState {
    fn push_outgoing(&mut self, data: Bytes) {
        self.outgoing_total += data.len();
        self.outgoing.push_back(OutgoingDatagram {
            datagram: Datagram { data },
            queued: None,
        });
    }

    fn drop_head(&mut self) -> Option<OutgoingDatagram> {
        let head = self.outgoing.pop_front()?;
        self.outgoing_total -= head.datagram.data.len();
        Some(head)
    }

    /// Apply CoDel to the outgoing queue, dropping datagrams from its head
    ///
    /// Called whenever the connection polls for transmits, which is when datagrams could be
    /// dequeued: RFC 8289's dequeue logic runs here, before packets are built, so that a packet
    /// is never started for datagrams that then get dropped. `max_datagram` is the size of one
    /// full packet. Returns whether any datagram was dropped.
    pub(super) fn manage_queue(
        &mut self,
        now: Instant,
        config: DatagramCodel,
        max_datagram: usize,
    ) -> bool {
        for datagram in self.outgoing.iter_mut().rev() {
            if datagram.queued.is_some() {
                break;
            }
            datagram.queued = Some(now);
        }
        let mut dropped = false;
        if let Some(max_delay) = config.max_delay {
            while let Some(head) = self.outgoing.front()
                && now.saturating_duration_since(head.queued.unwrap_or(now)) > max_delay
            {
                trace!("dropping outgoing datagram queued for over {max_delay:?}");
                self.drop_head();
                self.dropped_delay += 1;
                dropped = true;
            }
        }
        loop {
            let Some(head) = self.outgoing.front() else {
                self.codel.dropping = false;
                self.codel.first_above_time = None;
                return dropped;
            };
            let sojourn = now.saturating_duration_since(head.queued.unwrap_or(now));
            let ok_to_drop =
                self.codel
                    .ok_to_drop(sojourn, self.outgoing_total, max_datagram, now, config);
            if self.codel.dropping {
                if !ok_to_drop {
                    self.codel.dropping = false;
                    return dropped;
                }
                let drop_next = self.codel.drop_next.unwrap_or(now);
                if now < drop_next {
                    return dropped;
                }
                trace!(?sojourn, "codel: dropping outgoing datagram");
                self.drop_head();
                self.dropped_delay += 1;
                dropped = true;
                self.codel.count += 1;
                self.codel.drop_next =
                    Some(control_law(drop_next, config.interval, self.codel.count));
            } else if ok_to_drop {
                trace!(?sojourn, "codel: dropping outgoing datagram");
                self.drop_head();
                self.dropped_delay += 1;
                self.codel.dropping = true;
                // Resume near the previous drop rate if the queue was in the dropping state
                // recently, so that a persistent overload is controlled quickly.
                let delta = self.codel.count.saturating_sub(self.codel.last_count);
                let recent = self
                    .codel
                    .drop_next
                    .is_some_and(|t| now.saturating_duration_since(t) < 16 * config.interval);
                self.codel.count = if delta > 1 && recent { delta } else { 1 };
                self.codel.drop_next = Some(control_law(now, config.interval, self.codel.count));
                self.codel.last_count = self.codel.count;
                return true;
            } else {
                return dropped;
            }
        }
    }

    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<bool, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        if datagram.data.len() > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        let was_empty = self.recv_buffered == 0;
        while datagram.data.len() + self.recv_buffered > window {
            debug!("dropping stale datagram");
            self.recv();
        }

        self.recv_buffered += datagram.data.len();
        self.incoming.push_back(datagram);
        Ok(was_empty)
    }

    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            let Some(prev) = self.drop_head() else {
                break;
            };
            trace!(len = prev.datagram.data.len(), "dropping outgoing datagram");
            self.dropped_overflow += 1;
        }
    }

    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        let Some(total) = self.outgoing_total.checked_add(datagram_len) else {
            return false;
        };

        total <= send_buffer_size
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Returns whether any datagrams were dropped.
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let mut dropped = 0;
        self.outgoing.retain(|outgoing| {
            let datagram = &outgoing.datagram;
            let result = datagram.data.len() < max_payload;
            if !result {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.data.len(),
                    max_payload
                );
                self.outgoing_total -= datagram.data.len();
                dropped += 1;
            }
            result
        });
        self.dropped_overflow += dropped;
        dropped > 0
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write<'a, 'b>(
        &mut self,
        buf: &mut PacketBuilder<'a, 'b>,
        stat: &mut FrameStats,
    ) -> bool {
        let Some(head) = self.outgoing.front() else {
            return false;
        };

        if buf.frame_space_remaining() < head.datagram.size(true) {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            return false;
        }

        let head = self.drop_head().expect("checked above");
        buf.write_frame(head.datagram, stat);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        let x = self.incoming.pop_front()?.data;
        self.recv_buffered -= x.len();
        Some(x)
    }

    /// Drain up to `out.len()` buffered datagrams into `out`, in arrival order.
    ///
    /// Returns the number of datagrams written into `out` (which may be less than
    /// `out.len()` if fewer are buffered). Remaining datagrams stay queued.
    pub(super) fn recv_many(&mut self, out: &mut [Bytes]) -> usize {
        let n = out.len().min(self.incoming.len());
        let mut received_bytes = 0;
        for (i, d) in self.incoming.drain(..n).enumerate() {
            received_bytes += d.data.len();
            out[i] = d.data;
        }
        self.recv_buffered -= received_bytes;
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_space_for_accounts_for_new_datagram() {
        let mut state = DatagramState::default();
        state.push_outgoing(Bytes::from_static(&[0; 7]));
        state.push_outgoing(Bytes::from_static(&[0; 2]));
        state.outgoing_total = 9;

        state.make_space_for(4, 10);

        assert_eq!(state.outgoing.len(), 1);
        assert_eq!(state.outgoing[0].datagram.data.len(), 2);
        assert_eq!(state.outgoing_total, 2);
    }

    const PACKET: usize = 1200;

    fn config() -> DatagramCodel {
        DatagramCodel::default()
    }

    /// A queue that receives `arrivals` datagrams of `PACKET` bytes and sends at most `service`
    /// of them every millisecond for `millis` ms, running queue management each millisecond.
    /// Returns the queueing delay of the last datagram sent.
    fn simulate(
        state: &mut DatagramState,
        start: Instant,
        millis: u64,
        arrivals: usize,
        service: usize,
    ) -> Duration {
        let mut last_delay = Duration::ZERO;
        for ms in 0..millis {
            let now = start + Duration::from_millis(ms);
            for _ in 0..arrivals {
                state.push_outgoing(Bytes::from_static(&[0; PACKET]));
            }
            state.manage_queue(now, config(), PACKET);
            for _ in 0..service {
                let Some(sent) = state.drop_head() else {
                    break;
                };
                last_delay = now.saturating_duration_since(sent.queued.unwrap());
            }
        }
        last_delay
    }

    #[test]
    fn codel_lets_short_bursts_through() {
        let mut state = DatagramState::default();
        let start = Instant::now();
        // 50 ms worth of datagrams at once, drained well within one interval.
        for _ in 0..50 {
            state.push_outgoing(Bytes::from_static(&[0; PACKET]));
        }
        simulate(&mut state, start, 200, 0, 1);
        assert!(state.outgoing.is_empty());
        assert_eq!(state.dropped_delay, 0);
    }

    #[test]
    fn codel_bounds_a_standing_queue() {
        // 10% more arrivals than the path carries: without queue management the delay grows by
        // 100 ms every second.
        let start = Instant::now();
        let mut unmanaged = DatagramState::default();
        let mut delay = Duration::ZERO;
        for ms in 0..10_000u64 {
            let now = start + Duration::from_millis(ms);
            for _ in 0..(1 + usize::from(ms % 10 == 0)) {
                unmanaged.push_outgoing(Bytes::from_static(&[0; PACKET]));
            }
            for datagram in unmanaged.outgoing.iter_mut().rev() {
                if datagram.queued.is_some() {
                    break;
                }
                datagram.queued = Some(now);
            }
            let sent = unmanaged.drop_head().unwrap();
            delay = now.saturating_duration_since(sent.queued.unwrap());
        }
        assert!(delay >= Duration::from_millis(900), "{delay:?}");

        let mut managed = DatagramState::default();
        let mut max_late_delay = Duration::ZERO;
        for ms in 0..10_000u64 {
            let now = start + Duration::from_millis(ms);
            for _ in 0..(1 + usize::from(ms % 10 == 0)) {
                managed.push_outgoing(Bytes::from_static(&[0; PACKET]));
            }
            managed.manage_queue(now, config(), PACKET);
            if let Some(sent) = managed.drop_head() {
                let delay = now.saturating_duration_since(sent.queued.unwrap());
                if ms >= 5_000 {
                    max_late_delay = max_late_delay.max(delay);
                }
            }
        }
        assert!(managed.dropped_delay > 0);
        assert!(
            max_late_delay < Duration::from_millis(100),
            "queueing delay {max_late_delay:?} not controlled"
        );
    }

    #[test]
    fn codel_stops_dropping_once_the_queue_drains() {
        let mut state = DatagramState::default();
        let start = Instant::now();
        // Overload, then a drained queue: no drops once the delay is back under the target.
        simulate(&mut state, start, 2_000, 2, 1);
        assert!(state.dropped_delay > 0);
        let drained_at = start + Duration::from_millis(2_000);
        simulate(&mut state, drained_at, 5_000, 0, 10);
        assert!(state.outgoing.is_empty());
        let dropped = state.dropped_delay;
        let delay = simulate(
            &mut state,
            drained_at + Duration::from_millis(5_000),
            1_000,
            1,
            1,
        );
        assert_eq!(state.dropped_delay, dropped);
        assert!(delay < config().target);
        assert!(!state.codel.dropping);
    }

    #[test]
    fn max_delay_bounds_an_unresponsive_overload() {
        // Twice the path's rate, constantly: CoDel alone falls behind.
        let start = Instant::now();
        let run = |config: DatagramCodel| {
            let mut state = DatagramState::default();
            let mut max_late_delay = Duration::ZERO;
            for ms in 0..5_000u64 {
                let now = start + Duration::from_millis(ms);
                for _ in 0..2 {
                    state.push_outgoing(Bytes::from_static(&[0; PACKET]));
                }
                state.manage_queue(now, config, PACKET);
                if let Some(sent) = state.drop_head()
                    && ms >= 2_500
                {
                    max_late_delay =
                        max_late_delay.max(now.saturating_duration_since(sent.queued.unwrap()));
                }
            }
            max_late_delay
        };
        let codel_only = run(config());
        assert!(codel_only > Duration::from_millis(500), "{codel_only:?}");
        let capped = run(DatagramCodel {
            max_delay: Some(Duration::from_millis(50)),
            ..config()
        });
        assert!(capped <= Duration::from_millis(50), "{capped:?}");
    }

    #[test]
    fn codel_keeps_a_single_waiting_datagram() {
        // One packet's worth is not a standing queue, however long it waits (e.g. cwnd-blocked).
        let mut state = DatagramState::default();
        let start = Instant::now();
        state.push_outgoing(Bytes::from_static(&[0; PACKET]));
        for ms in 0..2_000 {
            state.manage_queue(start + Duration::from_millis(ms), config(), PACKET);
        }
        assert_eq!(state.outgoing.len(), 1);
        assert_eq!(state.dropped_delay, 0);
    }

    #[test]
    fn make_space_for_handles_overflowing_capacity_check() {
        let mut state = DatagramState::default();
        state.push_outgoing(Bytes::from_static(&[0]));
        state.outgoing_total = usize::MAX - 1;

        state.make_space_for(2, usize::MAX);

        assert!(state.outgoing.is_empty());
        assert_eq!(state.outgoing_total, usize::MAX - 2);
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}
