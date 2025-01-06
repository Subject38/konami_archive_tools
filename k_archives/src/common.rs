use crate::mar::MarCipher;
use rand::{distributions::Uniform, Rng};
use std::io::{Cursor, Error, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};
use std::{collections::HashMap, fs::File, path::PathBuf};
use thiserror::Error;

// enum used in both extdrmfs and drmfs as the handle for their file abstractions
pub enum CommonFile<'a> {
    File(File),
    KFile(KFile<'a>),
}

impl<'a> CommonFile<'a> {
    pub fn size(&self) -> u64 {
        match self {
            Self::File(file) => file.metadata().unwrap().len(), // if this ever fails we're cooked anyways...
            Self::KFile(file) => file.size(),
        }
    }
}

impl<'a> Read for CommonFile<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.read(buf),
            Self::KFile(file) => file.read(buf),
        }
    }
}

impl<'a> Seek for CommonFile<'a> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            Self::File(file) => file.seek(pos),
            Self::KFile(file) => file.seek(pos),
        }
    }
}

// Struct containing all the info needed to build a KFile object
// from a KArchive
#[derive(Debug, Clone)]
pub(crate) struct KFileInfo {
    pub(crate) size: u64,
    pub(crate) offset: u64,
    // might want to use an enum or otherwise in the future, but i don't mind hacking this for now
    pub(crate) cipher: Option<MarCipher>,
}

pub(crate) enum InternalFile<'a> {
    RealFile(File),
    Buffer(Cursor<&'a [u8]>),
}

impl<'a> Read for InternalFile<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            InternalFile::RealFile(file) => file.read(buf),
            InternalFile::Buffer(file) => file.read(buf),
        }
    }
}

impl<'a> Seek for InternalFile<'a> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        match self {
            InternalFile::RealFile(file) => file.seek(pos),
            InternalFile::Buffer(file) => file.seek(pos),
        }
    }
}

pub struct KFile<'a> {
    pub name: PathBuf,
    file: InternalFile<'a>,
    info: KFileInfo,
    pos: u64,
}

impl<'a> KFile<'a> {
    fn open(
        name: PathBuf,
        file: Option<File>,
        info: KFileInfo,
        buffer: Option<&'a [u8]>,
    ) -> std::io::Result<Self> {
        if let Some(buffer) = buffer {
            let mut cursor = Cursor::new(buffer);
            cursor.seek(SeekFrom::Start(info.offset))?;
            Ok(Self {
                name,
                file: InternalFile::Buffer(cursor),
                info,
                pos: 0,
            })
        } else if let Some(mut file) = file {
            file.seek(SeekFrom::Start(info.offset))?;
            Ok(Self {
                name,
                file: InternalFile::RealFile(file),
                info,
                pos: 0,
            })
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "need either a file or a file buffer...",
            ))
        }
    }

    pub fn size(&self) -> u64 {
        self.info.size
    }
}

impl<'a> Read for KFile<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.info.size {
            return Ok(0);
        }
        // In both cases we still need to read from the underlying file to the buffer.
        let bytes_to_read = usize::min(buf.len(), (self.info.size - self.pos) as usize);
        let ret_val = self.file.read(&mut buf[..bytes_to_read])?;
        self.pos += ret_val as u64;
        if let Some(cipher) = &mut self.info.cipher {
            // gitadora mar files use a non seekable 4 byte block cipher with a 4 byte key and iv.
            // it's entirely self rolled and somewhat annoying to implement in a re-entrant manner.
            // this implementation works though. random access is however not possible currently
            // without a method for seeking the cipher in constant time rather than O(N)
            cipher.crypt(&mut buf[..ret_val]);
        }
        Ok(ret_val)
    }
}

impl<'a> Seek for KFile<'a> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        if let Some(cipher) = &mut self.info.cipher {
            cipher.seek(pos)?;
        }
        // have to manually implement the seek logic here...
        // they're all fairly simple though
        match pos {
            SeekFrom::Start(n) => {
                self.file.seek(SeekFrom::Start(self.info.offset + n))?;
                self.pos = n
            }
            SeekFrom::End(n) => {
                if n < 0 && n.unsigned_abs() > self.info.size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Tried to seek to before the start of the file...",
                    ));
                }
                self.file.seek(SeekFrom::Start(
                    (self.info.offset + self.info.size).saturating_add_signed(n),
                ))?;
                self.pos = self.info.size.saturating_add_signed(n)
            }
            SeekFrom::Current(n) => {
                if n < 0 && n.unsigned_abs() > self.pos {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Tried to seek to before the start of the file...",
                    ));
                }
                self.file.seek(SeekFrom::Current(n))?;
                self.pos = self.pos.saturating_add_signed(n)
            }
        };
        Ok(self.pos)
    }
}

#[derive(Debug, Clone)]
struct KArchiveInner {
    path: PathBuf,
    files: HashMap<PathBuf, KFileInfo>,
    // optional buffer to be used in special circumstances...
    buffer: Option<Vec<u8>>,
}

// because of games with multipart updates, we actually need a vector of archive structs.
// the old one is renamed to inner, and the new one exists to resolve which archive is being accessed
#[derive(Debug, Clone)]
pub struct KArchive {
    archives: Vec<KArchiveInner>,
}

impl KArchive {
    pub(crate) fn add_archive(&mut self, arc: &mut Self) {
        self.archives.append(&mut arc.archives)
    }

    pub(crate) fn init_empty() -> Self {
        Self {
            archives: Vec::new(),
        }
    }

    pub(crate) fn new(
        path: PathBuf,
        files: HashMap<PathBuf, KFileInfo>,
        buffer: Option<Vec<u8>>,
    ) -> Self {
        Self {
            archives: vec![KArchiveInner {
                path,
                files,
                buffer,
            }],
        }
    }

    pub fn list_files(&self) -> Vec<PathBuf> {
        let mut res = Vec::new();
        self.archives.iter().for_each(|archive| {
            let inner: Vec<_> = archive.files.keys().cloned().collect();
            res.append(&mut inner.clone());
        });
        res
    }

    pub fn open(&self, path: &Path) -> std::io::Result<KFile> {
        for archive in &self.archives {
            if let Some(info) = archive.files.get(path) {
                match &archive.buffer {
                    Some(buffer) => {
                        return KFile::open(path.into(), None, info.clone(), Some(buffer))
                    }
                    None => {
                        return KFile::open(
                            path.into(),
                            Some(File::open(&archive.path)?),
                            info.clone(),
                            None,
                        );
                    }
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File {} does not exist in the archive", path.display()),
        ))
    }

    pub fn exists(&self, path: &Path) -> bool {
        self.archives
            .iter()
            .find_map(|archive| archive.files.get(path))
            .is_some()
    }

    pub fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        let mut file = self.open(path)?;
        let mut buf = Vec::with_capacity(file.info.size as usize);
        std::io::copy(&mut file, &mut buf)?;
        Ok(buf)
    }

    pub fn guess_contents_folder(&self) -> Option<PathBuf> {
        Some(
            self.list_files()
                .iter()
                .find(|path| path.to_str().unwrap().contains("contents"))?
                .to_str()?
                .split_inclusive("contents")
                .collect::<Vec<&str>>()[0]
                .into(),
        )
    }
}

#[derive(Error, Debug)]
pub enum KArchiveError {
    #[error("io error encountered: {0}")]
    IoError(#[from] std::io::Error),
    #[error("parse error encountered: {0}")]
    ParseError(String),
    #[error("parse error encountered in binread: {0}")]
    BinreadError(#[from] binread::Error),
    #[error("from utf8 error encountered: {0}")]
    FromUTF8Error(#[from] std::string::FromUtf8Error),
    #[error("error encountered: {0}")]
    Other(&'static str),
}

/// What should this function be called? It benchmarks the underlying fs to
/// hopefully detect whether we're on a network share or some other high
/// latency fs. But it returns either a buffer to use or nothing
/// which has nothing to do with the name...
pub(crate) fn benchmark(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    let mut bench_file = File::open(path)?;
    let size = bench_file.metadata()?.len();
    let start = Instant::now();
    let mut rng = rand::thread_rng();
    let range = Uniform::new(0, size);
    let target_duration = Duration::from_millis(4); // 4 ms seems like a reasonable target to hit
    for loc in (0..10).map(|_| rng.sample(range)) {
        bench_file.seek(SeekFrom::Start(loc))?;
        // i don't care whether the read actually does anything. only that it happens.
        // i don't want to risk read_exact throwing an irrelevant error
        let _ = bench_file.read(&mut [0])?; // read a single byte

        // we check on every iteration in case we're in a particularly high latency situation
        // ie. sshfs on not a local network. the benchmark could take easily a few seconds in that situation
        // but we would know that the latency is high after even the first iteration...
        let elapsed = Instant::now().duration_since(start);
        if elapsed > target_duration {
            eprintln!("k_archives: High latency storage detected, reading full file into memory to allow faster processing.");
            let mut buf = Vec::with_capacity(size as usize);
            bench_file.seek(SeekFrom::Start(0))?;
            bench_file.read_to_end(&mut buf)?;
            return Ok(Some(buf));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn windows_path_join() {
        let mut file_list: HashMap<PathBuf, KFileInfo> = HashMap::new();
        file_list.insert(
            PathBuf::from("reeeeeeeeeeee").join("reeeeeeeeee"),
            KFileInfo {
                size: 0,
                offset: 0,
                cipher: None,
            },
        );
        let archive = KArchive::new("big".into(), file_list, None);
        assert!(archive.exists(&PathBuf::from("reeeeeeeeeeee/reeeeeeeeee")))
    }
}
