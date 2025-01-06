use binread::{BinRead, NullString};
use std::fs::File;
use std::path::PathBuf;

use crate::common::*;
#[allow(dead_code)]
#[derive(BinRead)]
#[br(magic = b"ULST")]
pub struct LstFile {
    #[br(align_after = 0x10)]
    pub file_count: u16,

    #[br(count = file_count)]
    pub files: Vec<LstEntry>,
}

#[allow(dead_code)]
#[derive(BinRead)]
pub struct LstEntry {
    #[br(pad_size_to = 0x20)]
    pub name: NullString,

    #[br(pad_size_to = 0x40)]
    pub file_name: NullString,

    #[br(pad_size_to = 0x8)]
    pub checksum_type: NullString,

    #[br(pad_size_to = 0x28)]
    pub checksum: NullString,

    #[br(pad_after = 0x10)]
    pub file_size: u64,
}

pub(crate) fn parse(path: PathBuf) -> Result<KArchive, KArchiveError> {
    let mut file = File::open(&path)?;
    let mut archive = KArchive::init_empty();
    let lst_file = LstFile::read(&mut file)?;
    for entry in lst_file.files {
        if let Ok(mut arc) = super::mount(path.with_file_name(entry.file_name.to_string())) {
            archive.add_archive(&mut arc)
        } else {
            eprintln!(
                "LST: Failed to mount archive: {}",
                entry.file_name.to_string()
            )
        }
    }
    Ok(archive)
}
