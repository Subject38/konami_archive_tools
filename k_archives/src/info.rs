use std::fs;
use std::path::PathBuf;

use crate::common::*;

pub(crate) fn parse(path: PathBuf) -> Result<KArchive, KArchiveError> {
    let contents = fs::read_to_string(&path)?;
    let mut archive = KArchive::init_empty();
    let mut file_names = Vec::new();
    for line in contents.lines() {
        if line.starts_with("FILE") {
            file_names.push(PathBuf::from(line.strip_prefix("FILE : ").unwrap().trim()))
        }
    }
    for name in file_names {
        if let Ok(mut arc) = super::mount(path.with_file_name(&name)) {
            archive.add_archive(&mut arc)
        } else {
            eprintln!("INFO: Failed to mount archive: {:?}", name)
        }
    }
    Ok(archive)
}
