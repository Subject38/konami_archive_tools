mod bar;
mod cab;
mod common;
mod d2;
mod info;
mod lst;
mod mar;
mod qar;
use std::{io::Read, path::PathBuf};

pub use crate::common::*;

pub fn mount(path: PathBuf) -> Result<KArchive, KArchiveError> {
    let mut archive = std::fs::File::open(&path)?;
    // read the first 4 bytes to see which type it is
    let mut magic = [0_u8; 4];
    archive.read_exact(&mut magic)?;
    match &magic {
        // QAR\0
        b"QAR\0" => crate::qar::parse(path),
        // MASM (full magic is MASMAR0 but this is good enough to know where to go)
        b"MASM" => crate::mar::parse(path),
        // ULST. this is a list file that contains the filenames, sizes, and hashes of a multi file update
        // seems to only be used by gitadora and can be used to mount all of them at once rather than individually
        b"ULST" => crate::lst::parse(path),
        // this isn't actually a magic number, this file is just a plain text description with the same info as ULST
        b"NAME" => crate::info::parse(path),
        // Cabinet files are used for some games. They usually contain an arcfile inside as well as a file list
        b"MSCF" => crate::cab::parse(path),
        // neither bar nor d2 have magic numbers, but bar can be weird and have a different extension (car in iidx preload),
        // so check if extension is d2, otherwise use the bar parser
        _ => {
            if path
                .extension()
                .is_some_and(|ext| ext == "d2" || ext == "dat")
            {
                crate::d2::parse(path)
            } else {
                crate::bar::parse(path)
            }
        }
    }
}
