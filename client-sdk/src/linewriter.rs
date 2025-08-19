//! Line-oriented `Write` adapters.
//!
//! Converts arbitrary byte streams into UTF-8 lines and emits each line to a handler.
//! Useful for piping program output into stdout or a file without interleaving.
//! It can be used in Vanadium V-App clients to process and display (or log) the printed output
//! of the V-App.
//!
//! Types:
//! - [`Sink`]: no-op writer; accepts bytes and discards them.
//! - [`PrintWriter`]: writes one logical line per call to stdout; optional millisecond timestamp.
//! - [`FileLineWriter`]: writes one logical line per call to a file; optional millisecond timestamp.
//!
//! Behavior:
//! - Bytes are buffered until `\n`, then the line (without the newline) is dispatched.
//! - Partial trailing data is flushed on [`Write::flush`] and on drop.
//! - Lines are decoded with `String::from_utf8_lossy`.
//! - Timestamp format: `"[seconds.millis] line"` (UNIX time).

use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

/// Converts byte streams into lines and calls the handler for every line.
trait LineHandler {
    fn on_line(&mut self, line: &str) -> io::Result<()>;
}

#[derive(Debug)]
struct LineDispatcher<H: LineHandler> {
    buffer: Vec<u8>,
    handler: H,
}

impl<H: LineHandler> LineDispatcher<H> {
    fn new(handler: H) -> Self {
        Self {
            buffer: Vec::new(),
            handler,
        }
    }

    #[inline]
    fn on_line(&mut self, bytes: &[u8]) -> io::Result<()> {
        let line = String::from_utf8_lossy(bytes);
        self.handler.on_line(&line)
    }

    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut start = 0;
        for (i, &b) in data.iter().enumerate() {
            if b == b'\n' {
                self.buffer.extend_from_slice(&data[start..i]);
                let line_bytes = std::mem::take(&mut self.buffer);
                self.on_line(&line_bytes)?;
                start = i + 1;
            }
        }
        self.buffer.extend_from_slice(&data[start..]);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let tmp = std::mem::take(&mut self.buffer);
            self.on_line(&tmp)?;
        }
        Ok(())
    }
}

fn format_line(with_timestamp: bool, line: &str) -> String {
    if with_timestamp {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let s = ms / 1000;
        let ms_frac = (ms % 1000) as u128;
        format!("[{s}.{ms_frac:03}] {line}")
    } else {
        line.to_owned()
    }
}

impl<H: LineHandler> Drop for LineDispatcher<H> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

/// Sink writer: implements `Write` by doing nothing
#[derive(Debug, Default)]
pub struct Sink;

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Console writer
pub struct PrintWriter {
    inner: LineDispatcher<StdoutHandler>,
}

impl fmt::Debug for PrintWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrintWriter").finish()
    }
}

struct StdoutHandler {
    with_timestamp: bool,
}

impl LineHandler for StdoutHandler {
    fn on_line(&mut self, line: &str) -> io::Result<()> {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{}", format_line(self.with_timestamp, line))
    }
}

impl PrintWriter {
    pub fn new(with_timestamp: bool) -> Self {
        Self {
            inner: LineDispatcher::new(StdoutHandler { with_timestamp }),
        }
    }
}

impl Write for PrintWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// File writer
#[derive(Debug)]
pub struct FileLineWriter {
    inner: LineDispatcher<FileHandler>,
}

#[derive(Debug)]
struct FileHandler {
    with_timestamp: bool,
    path: PathBuf,
    overwrite: bool,
    writer: Option<BufWriter<File>>,
}

impl LineHandler for FileHandler {
    fn on_line(&mut self, line: &str) -> io::Result<()> {
        if self.writer.is_none() {
            let file: File = if self.overwrite {
                // Truncate/create on first actual write
                File::create(&self.path)?
            } else {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)?
            };
            self.writer = Some(BufWriter::new(file));
        }

        let w = self.writer.as_mut().expect("writer must be initialized");
        writeln!(w, "{}", format_line(self.with_timestamp, line))?;
        w.flush()
    }
}

impl FileLineWriter {
    /// `overwrite = false` will append if file exists
    pub fn new(path: &str, with_timestamp: bool, overwrite: bool) -> Self {
        let handler = FileHandler {
            with_timestamp,
            path: PathBuf::from(path),
            overwrite,
            writer: None,
        };

        Self {
            inner: LineDispatcher::new(handler),
        }
    }
}

impl Write for FileLineWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn tmp_path(prefix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let pid = std::process::id();
        p.push(format!("{}_{}_{}.log", prefix, pid, ts));
        p
    }

    #[test]
    fn line_dispatcher_splits_and_flushes() {
        struct Collect<'a>(&'a mut Vec<String>);
        impl<'a> LineHandler for Collect<'a> {
            fn on_line(&mut self, line: &str) -> io::Result<()> {
                self.0.push(line.to_string());
                Ok(())
            }
        }

        let mut out = Vec::new();

        {
            let mut ld = LineDispatcher::new(Collect(&mut out));
            assert_eq!(ld.write(b"hello\nwor").unwrap(), 9);
            assert_eq!(ld.write(b"ld\nlast").unwrap(), 7);
            ld.flush().unwrap();
        }

        assert_eq!(
            out,
            vec!["hello".to_string(), "world".to_string(), "last".to_string()]
        );
    }

    #[test]
    fn sink_write_and_flush() {
        let mut s = Sink;
        assert_eq!(s.write(b"abc").unwrap(), 3);
        s.flush().unwrap();
    }

    #[test]
    fn file_line_writer_with_timestamp_format() {
        let path = tmp_path("stream_ts");
        {
            let mut w = FileLineWriter::new(path.to_string_lossy().as_ref(), true, true);
            w.write_all(b"foo").unwrap();
            w.flush().unwrap();
        }

        let content = fs::read_to_string(&path).unwrap();
        let line = content.trim_end_matches('\n');
        let (ts, rest) = line
            .strip_prefix('[')
            .and_then(|s| s.split_once(']'))
            .unwrap();
        assert_eq!(rest, " foo");
        let (sec, ms) = ts.split_once('.').unwrap();
        assert!(sec.chars().all(|c| c.is_ascii_digit()));
        assert!(ms.len() == 3 && ms.chars().all(|c| c.is_ascii_digit()));

        let _ = fs::remove_file(&path);
    }
}
