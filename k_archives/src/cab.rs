use crate::common::*;
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom};
use std::path::PathBuf;

fn read_file_name<T>(rdr: &mut T) -> Result<String, KArchiveError>
where
    T: BufRead + Seek,
{
    let mut buf = Vec::<u8>::new();
    rdr.read_until(0, &mut buf)?;
    Ok(String::from_utf8(
        buf.strip_suffix(&[0])
            .ok_or(KArchiveError::Other(
                "Failed to strip suffix (malformed or incomplete archive)",
            ))?
            .to_vec(),
    )?)
}

fn read_folder<T>(
    rdr: &mut T,
    mut full_path: PathBuf,
    files: &mut HashMap<PathBuf, KFileInfo>,
) -> Result<(), KArchiveError>
where
    T: BufRead + Seek,
{
    let action = rdr.read_u8()?;
    full_path.push(read_file_name(rdr)?);
    let param = rdr.read_i32::<LittleEndian>()?;
    match action {
        0x00 => {
            files.insert(
                full_path,
                KFileInfo {
                    size: param as u64,
                    offset: rdr.stream_position()?,
                    cipher: None,
                },
            );
            rdr.seek(SeekFrom::Current(param as i64))?;
        }
        0x01 => {
            let mut entries = param;
            while entries > 0 {
                read_folder(rdr, full_path.clone(), files)?;
                entries -= 1;
            }
        }
        _ => unreachable!("Only two types of entries"),
    }
    Ok(())
}

pub(crate) fn parse(path: PathBuf) -> Result<KArchive, KArchiveError> {
    let cab_file = File::open(&path)?;
    let mut cabinet = cab::Cabinet::new(cab_file)?;
    let arcsize = cabinet
        .get_file_entry("arcfile")
        .ok_or(KArchiveError::Other("Failed to get arcfile from cab"))?
        .uncompressed_size()
        .into();
    // I've never seen a cab file that didn't just have an arcfile and filelist inside so assume the structure will be like that until proven wrong
    let mut arcfile = BufReader::new(cabinet.read_file("arcfile")?);
    // Due to bugs with the cab crate, i'm storing the arcfile buffer inside the KArchive struct for this specific format.
    // If interfacing with the cab file directly becomes viable, i'll switch away from this method...
    let mut buf = Vec::with_capacity(arcsize as usize);
    arcfile.read_to_end(&mut buf)?;
    let mut cursor = Cursor::new(buf);
    let mut files: HashMap<PathBuf, KFileInfo> = HashMap::new();
    while cursor.stream_position()? != arcsize {
        read_folder(&mut cursor, PathBuf::from(""), &mut files)?;
    }
    // Leak the buffer to get a static lifetime slice. This is fine because
    // it's guaranteed to live until the program is terminated anyways...
    let buffer = cursor.into_inner();
    Ok(KArchive::new(path, files, Some(buffer)))
}
