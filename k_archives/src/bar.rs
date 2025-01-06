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
    rdr.seek(SeekFrom::Current(256 - size as i64))?;
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
    // Skip the first 10 bytes
    file.seek_relative(10)?;
    let file_count = file.read_u16::<LittleEndian>()?;
    let parse_result = (0..file_count).try_for_each(|_| {
        let name = read_file_name(&mut file)?;
        // bar files are weird. in M39A bars, the filename takes 252 bytes rather than 256
        // So let's check if we just read one of those
        if file.read_i32::<LittleEndian>()? == -1 {
            file.seek_relative(-8)?;
        } else {
            file.seek_relative(-4)?;
        }
        let magic1 = file.read_i32::<LittleEndian>()?;
        let magic2 = file.read_i32::<LittleEndian>()?;
        if magic1 != 3 || magic2 != -1 {
            return Err(KArchiveError::ParseError(format!(
                "magic numbers are wrong: {} {}",
                magic1, magic2
            )));
        }
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
            92, 74, 69, 65, 50, 48, 50, 52, 48, 52, 49, 53, 48, 48, 99, 111, 110, 116, 101, 110,
            116, 115, 92, 53, 92, 102, 92, 56, 92, 54, 52, 52, 102, 48, 52, 99, 57, 102, 52, 48,
            49, 50, 100, 100, 55, 50, 53, 102, 57, 50, 49, 52, 51, 54, 55, 54, 98, 97, 99, 99, 55,
            51, 52, 50, 52, 54, 0, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254, 254,
            254, 254, 254, 254, 254, 254,
        ]);
        let mut filename = BufReader::new(cursor);
        assert_eq!(
            read_file_name(&mut filename).unwrap(),
            "JEA2024041500contents/5/f/8/644f04c9f4012dd725f92143676bacc734246"
        )
    }
}
