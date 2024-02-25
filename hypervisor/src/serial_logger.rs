//! The module containing the serial port logger implementation.

use crate::x86_instructions::{inb, outb};
use core::{fmt, fmt::Write};
use spin::Mutex;

/// Initializes the logger instance.
pub(crate) fn init(level: log::LevelFilter) {
    log::set_logger(&SERIAL_LOGGER)
        .map(|()| log::set_max_level(level))
        .unwrap();
}

struct SerialLogger {
    port: Mutex<Serial>,
}
impl SerialLogger {
    const fn new() -> Self {
        Self {
            port: Mutex::new(Serial {}),
        }
    }

    fn lock(&self) -> spin::MutexGuard<'_, Serial> {
        self.port.lock()
    }

    fn apic_id() -> u32 {
        // See: (AMD) CPUID Fn0000_0001_EBX LocalApicId, LogicalProcessorCount, CLFlush
        // See: (Intel) Table 3-8. Information Returned by CPUID Instruction
        x86::cpuid::cpuid!(0x1).ebx >> 24
    }
}
impl log::Log for SerialLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            let _ = writeln!(
                self.lock(),
                "CPU#{}:{}: {}",
                Self::apic_id(),
                record.level(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

struct Serial;

impl Write for Serial {
    // Writes bytes `string` to the serial port.
    fn write_str(&mut self, string: &str) -> Result<(), fmt::Error> {
        const UART_COM1: u16 = 0x3f8;
        const UART_OFFSET_TRANSMITTER_HOLDING_BUFFER: u16 = 0;
        const UART_OFFSET_LINE_STATUS: u16 = 5;

        for byte in string.bytes() {
            while (inb(UART_COM1 + UART_OFFSET_LINE_STATUS) & 0x20) == 0 {}
            outb(UART_COM1 + UART_OFFSET_TRANSMITTER_HOLDING_BUFFER, byte);
        }
        Ok(())
    }
}

static SERIAL_LOGGER: SerialLogger = SerialLogger::new();
