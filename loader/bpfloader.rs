/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! BPF loader for system and vendor applications
use android_logger::AndroidLogger;
use log::{error, info, Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::{
    cmp::max,
    env,
    fs::File,
    io::{LineWriter, Write},
    os::fd::FromRawFd,
    panic,
    sync::{Arc, Mutex},
};

enum KernelLevel {
    // Commented out unused due to rust complaining...
    // EMERG = 0,
    // ALERT = 1,
    // CRIT = 2,
    ERR = 3,
    WARNING = 4,
    // NOTICE = 5,
    INFO = 6,
    DEBUG = 7,
}

fn level_to_kern_level(level: &Level) -> u8 {
    let result = match level {
        Level::Error => KernelLevel::ERR,
        Level::Warn => KernelLevel::WARNING,
        Level::Info => KernelLevel::INFO,
        Level::Debug => KernelLevel::DEBUG,
        Level::Trace => KernelLevel::DEBUG,
    };
    result as u8
}

/// A logger implementation to enable bpfloader to write to kmsg on error as
/// bpfloader runs at early init prior to the availability of standard Android
/// logging. If a crash were to occur, we can disrupt boot, and therefore we
/// need the ability to access the logs on the serial port.
pub struct BpfKmsgLogger {
    log_level: LevelFilter,
    tag: String,
    kmsg_writer: Arc<Mutex<Box<dyn Write + Send>>>,
    a_logger: AndroidLogger,
}

impl Log for BpfKmsgLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.log_level || self.a_logger.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        if record.metadata().level() <= self.log_level {
            let mut writer = self.kmsg_writer.lock().unwrap();
            write!(
                writer,
                "<{}>{}: {}",
                level_to_kern_level(&record.level()),
                self.tag,
                record.args()
            )
            .unwrap();
            let _ = writer.flush();
        }
        self.a_logger.log(record);
    }

    fn flush(&self) {}
}

impl BpfKmsgLogger {
    /// Initialize the logger
    pub fn init(kmsg_file: File) -> Result<(), SetLoggerError> {
        let alog_level = LevelFilter::Info;
        let kmsg_level = LevelFilter::Error;

        let log_config = android_logger::Config::default()
            .with_tag("BpfLoader-rs")
            .with_max_level(alog_level)
            .with_log_buffer(android_logger::LogId::Main)
            .format(|buf, record| writeln!(buf, "{}", record.args()));

        let writer = Box::new(LineWriter::new(kmsg_file)) as Box<dyn Write + Send>;
        log::set_max_level(max(alog_level, kmsg_level));
        log::set_boxed_logger(Box::new(BpfKmsgLogger {
            log_level: kmsg_level,
            tag: "BpfLoader-rs".to_string(),
            kmsg_writer: Arc::new(Mutex::new(writer)),
            a_logger: AndroidLogger::new(log_config),
        }))
    }
}

#[cfg(enable_libbpf)]
fn load_libbpf_progs() {
    // Libbpf loader functionality here.
    info!("Loading libbpf programs");
}

#[cfg(not(enable_libbpf))]
fn load_libbpf_progs() {
    // Empty stub for feature flag disabled case
    info!("Loading of libbpf programs DISABLED");
}

fn main() {
    let kmsg_fd = env::var("ANDROID_FILE__dev_kmsg").unwrap().parse::<i32>().unwrap();
    // SAFETY: The init script opens this file for us
    let kmsg_file = unsafe { File::from_raw_fd(kmsg_fd) };

    if let Err(logger) = BpfKmsgLogger::init(kmsg_file) {
        error!("BpfLoader-rs: log::setlogger failed: {}", logger);
    }

    // Redirect panic messages to both logcat and serial port
    panic::set_hook(Box::new(|panic_info| {
        error!("{}", panic_info);
    }));

    load_libbpf_progs();
    info!("Done, loading legacy BPF progs");

    // SAFETY: Linking in the existing legacy bpfloader functionality.
    // Any of the four following bindgen functions can abort() or exit()
    // on failure and execNetBpfLoadDone() execve()'s.
    unsafe {
        bpf_android_bindgen::initLogging();
        bpf_android_bindgen::createBpfFsSubDirectories();
        bpf_android_bindgen::legacyBpfLoader();
        bpf_android_bindgen::execNetBpfLoadDone();
    }
}
