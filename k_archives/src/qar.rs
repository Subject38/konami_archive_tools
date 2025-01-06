use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Seek, SeekFrom};
use std::path::PathBuf;

use byteorder::{LittleEndian, ReadBytesExt};

use crate::common::*;

fn read_file_name<T>(rdr: &mut T) -> Result<String, KArchiveError>
where
    T: BufRead + Seek,
{
    let mut buf = Vec::<u8>::new();
    let size = rdr.read_until(0, &mut buf)?;
    rdr.seek(SeekFrom::Current(132 - size as i64))?;
    Ok(String::from_utf8(
        buf.strip_suffix(&[0])
            .ok_or(KArchiveError::Other(
                "Failed to strip suffix (malformed or incomplete archive)",
            ))?
            .to_vec(),
    )?
    .trim_start_matches(['.', '\\'])
    .replace('\\', "/")
    .to_string())
}

pub(crate) fn parse(path: PathBuf) -> Result<KArchive, KArchiveError> {
    let buffer = benchmark(&path)?;
    let mut file = match &buffer {
        Some(buf) => BufReader::new(InternalFile::Buffer(Cursor::new(buf))),
        None => BufReader::new(InternalFile::RealFile(File::open(&path)?)),
    };
    let mut files: HashMap<PathBuf, KFileInfo> = HashMap::new();
    // we already validated the magic so just skip it...
    file.seek_relative(4)?;
    let file_count = file.read_u32::<LittleEndian>()?;
    let parse_result: Result<(), KArchiveError> = (0..file_count).try_for_each(|_| {
        let name = read_file_name(&mut file)?;
        file.seek_relative(4)?;
        let size = file.read_u32::<LittleEndian>()? as u64;
        file.seek_relative(4)?;
        let offset = file.stream_position()?;
        file.seek_relative(size as i64)?;
        files.insert(
            name.into(),
            KFileInfo {
                size,
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
            92, 46, 92, 75, 70, 67, 92, 99, 111, 110, 116, 101, 110, 116, 115, 92, 56, 92, 99, 92,
            97, 92, 53, 54, 56, 50, 102, 51, 57, 97, 102, 52, 53, 51, 56, 102, 52, 97, 100, 55, 56,
            48, 54, 99, 48, 99, 57, 55, 100, 53, 51, 55, 49, 97, 98, 52, 57, 97, 98, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        let mut filename = BufReader::new(cursor);
        assert_eq!(
            read_file_name(&mut filename).unwrap(),
            "KFC/contents/8/c/a/5682f39af4538f4ad7806c0c97d5371ab49ab"
        )
    }
}
