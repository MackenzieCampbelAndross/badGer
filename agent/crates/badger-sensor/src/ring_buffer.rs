use crate::bpf_types::BadgerBpfEvent;
use badger_common::{BadgerError, BadgerResult};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info};

pub struct EventRingBufferReader {
    is_running: Arc<AtomicBool>,
    dropped_events: Arc<AtomicU64>,
    total_received: Arc<AtomicU64>,
}

impl Default for EventRingBufferReader {
    fn default() -> Self {
        Self::new()
    }
}

impl EventRingBufferReader {
    pub fn new() -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
            dropped_events: Arc::new(AtomicU64::new(0)),
            total_received: Arc::new(AtomicU64::new(0)),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn start_polling(
        &self,
        ring_buf_map: aya::maps::Map,
        tx: mpsc::Sender<BadgerBpfEvent>,
    ) -> BadgerResult<()> {
        use aya::maps::RingBuf;

        let mut ring_buf = RingBuf::try_from(ring_buf_map)
            .map_err(|e| BadgerError::Sensor(format!("Failed to initialize Aya RingBuf map: {}", e)))?;

        self.is_running.store(true, Ordering::SeqCst);
        let running_flag = self.is_running.clone();
        let dropped_counter = self.dropped_events.clone();
        let total_counter = self.total_received.clone();

        info!("eBPF Ring Buffer Reader active (capacity: 256KB bounded map)...");

        std::thread::spawn(move || {
            while running_flag.load(Ordering::SeqCst) {
                let mut had_events = false;
                while let Some(item) = ring_buf.next() {
                    had_events = true;
                    if item.len() >= std::mem::size_of::<BadgerBpfEvent>() {
                        let event: BadgerBpfEvent =
                            unsafe { std::ptr::read(item.as_ptr() as *const BadgerBpfEvent) };

                        total_counter.fetch_add(1, Ordering::Relaxed);

                        if let Err(_) = tx.blocking_send(event) {
                            // Downstream channel full or closed -> backpressure drop
                            dropped_counter.fetch_add(1, Ordering::Relaxed);
                        }
                    } else {
                        error!("Malformed ring buffer item received: length {}", item.len());
                        dropped_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }

                if !had_events {
                    // Small sleep when ring buffer is empty to yield CPU
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            info!("eBPF Ring Buffer Reader terminated gracefully.");
        });

        Ok(())
    }

    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }

    pub fn get_dropped_count(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    pub fn get_total_count(&self) -> u64 {
        self.total_received.load(Ordering::Relaxed)
    }
}
