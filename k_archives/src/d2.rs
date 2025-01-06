use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek, SeekFrom};
use std::path::PathBuf;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::common::*;

fn read_file_header<T>(rdr: &mut T) -> Result<(String, i64), KArchiveError>
where
    T: BufRead + Seek,
{
    // first byte of file header is always 1
    assert_eq!(rdr.read_u8()?, 1);
    let path_len = rdr.read_u32::<LittleEndian>()?;
    let filesize = rdr.read_u32::<LittleEndian>()?;
    // there's some weird checksum here, no idea how it's calculated...
    rdr.seek(SeekFrom::Current(0x10))?;
    let mut buf = vec![0; path_len as usize];
    rdr.read_exact(&mut buf)?;
    let name = String::from_utf8(buf)?;
    Ok((name, filesize as i64))
}

pub(crate) fn parse(path: PathBuf) -> Result<KArchive, KArchiveError> {
    let buffer = benchmark(&path)?;
    let mut file = match &buffer {
        Some(buf) => BufReader::new(InternalFile::Buffer(Cursor::new(buf))),
        None => BufReader::new(InternalFile::RealFile(File::open(&path)?)),
    };
    let mut files: HashMap<PathBuf, KFileInfo> = HashMap::new();
    let num_files = file.read_u32::<LittleEndian>()?;
    let _archive_size = file.read_u32::<LittleEndian>()?;
    let parse_result: Result<(), KArchiveError> = (0..num_files).try_for_each(|_| {
        let (name, size) = read_file_header(&mut file)?;
        let offset = file.stream_position()?;
        file.seek_relative(size)?;
        files.insert(
            name.into(),
            KFileInfo {
                size: size as u64,
                offset,
                cipher: None,
            },
        );
        Ok(())
    });
    match parse_result {
        Ok(_) => {}
        Err(e) => {
            eprintln!("k_archives: Error in archive parsing: {}", e);
            eprintln!("k_archives: Continuing with {} files parsed", files.len());
        }
    }
    Ok(KArchive::new(path, files, buffer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn test_filename() {
        let cursor = Cursor::new(vec![
            1, 58, 0, 0, 0, 46, 186, 0, 0, 206, 203, 163, 235, 41, 226, 210, 81, 64, 60, 119, 164,
            75, 147, 240, 0, 100, 47, 76, 77, 65, 47, 99, 111, 110, 116, 101, 110, 116, 115, 47,
            48, 47, 48, 47, 99, 47, 50, 99, 102, 52, 49, 100, 53, 99, 52, 50, 55, 57, 97, 50, 54,
            99, 101, 99, 53, 54, 52, 56, 57, 57, 100, 97, 50, 50, 57, 57, 49, 57, 57, 99, 97, 51,
            50,
        ]);
        let mut filename = BufReader::new(cursor);
        assert_eq!(
            read_file_header(&mut filename).unwrap(),
            (
                "d/LMA/contents/0/0/c/2cf41d5c4279a26cec564899da2299199ca32".into(),
                47662_i64
            )
        )
    }
}
