use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Seek};
use std::path::PathBuf;

use byteorder::{LittleEndian, ReadBytesExt};
use crc_any::{CRCu16, CRCu32};

use crate::common::*;

#[derive(Clone, Debug)]
pub(crate) struct MarCipher {
    keystream: MarKeystream,
    current_iterator: Option<MarKeystreamIterator>,
    // internal position of the cipher
    pos: u64,
    // size of the file we're crypting
    size: u64,
}

impl MarCipher {
    pub(crate) fn new(key: u32, iv: u32, size: u64) -> MarCipher {
        MarCipher {
            keystream: MarKeystream::new(key, iv),
            current_iterator: None,
            pos: 0,
            size,
        }
    }

    pub(crate) fn crypt(&mut self, mut data: &mut [u8]) {
        if self.pos == self.size || data.is_empty() {
            return;
        }

        let key_iterator = match self.current_iterator.as_mut() {
            Some(it) => {
                // We rewind the iterator if we're still on the previous block
                if self.pos % 4 != 0 {
                    it.rewind();
                }
                it
            }
            None => {
                let iterator = self.keystream.get_keystream(self.pos);
                self.current_iterator = Some(iterator);
                self.current_iterator.as_mut().unwrap()
            }
        };

        for key_block in key_iterator {
            if self.pos % 4 == 0 && self.pos + 4 > self.size {
                // Check if we need to handle a special case for the last block
                // it seems konami fucked up their own cipher implementation
                // and only modify the first byte in the last block of the file
                for k in key_block.iter().take((self.size - self.pos) as usize) {
                    data[0] ^= k;
                }
                self.pos = self.size;
                return;
            }

            if self.pos % 0x1000 == 0 {
                self.keystream
                    .add_checkpoint(self.pos, u32::from_le_bytes(key_block));
            }

            let mut idx = 0;
            for (k, d) in key_block
                .into_iter()
                .skip(self.pos as usize % 4) // align key block to data
                .zip(data.iter_mut())
            {
                *d ^= k;
                self.pos += 1;
                idx += 1;
            }
            data = &mut data[idx..];
            if data.is_empty() {
                break;
            }
        }
    }

    fn seek_internal(&mut self, new_pos: u64) -> u64 {
        self.current_iterator = None; // invalidate iterator
        self.pos = u64::min(self.size, new_pos);
        self.pos
    }
}

impl Seek for MarCipher {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match pos {
            std::io::SeekFrom::Start(x) => Ok(self.seek_internal(x)),
            std::io::SeekFrom::End(x) => {
                if x.is_negative() && x.unsigned_abs() > self.size {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "seeked beyond file size".to_string(),
                    ));
                }
                Ok(self.seek_internal(self.size.saturating_add_signed(x)))
            }
            std::io::SeekFrom::Current(x) => {
                if x.is_negative() && x.unsigned_abs() > self.pos {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "seeked beyond start of file".to_string(),
                    ));
                }
                Ok(self.seek_internal(self.pos.saturating_add_signed(x)))
            }
        }
    }
}

#[derive(Clone, Debug)]
struct MarKeystream {
    key: u32,
    subkeys: HashMap<u64, u32>,
}

impl MarKeystream {
    pub(crate) fn new(key: u32, iv: u32) -> MarKeystream {
        let first_subkey = MarKeystream::next_subkey(iv, key);
        MarKeystream {
            key,
            subkeys: HashMap::from([(0, first_subkey)]),
        }
    }

    /// Returns an iterator that yields a 4-byte array for each block in the keystream.
    /// The iterator will always start at the beginning of the block regardless if
    /// `pos` is in the middle or end of a block.
    pub(crate) fn get_keystream(&mut self, pos: u64) -> MarKeystreamIterator {
        // Blocks in Mar keystreams are 4 bytes long. We need to handle cases where
        // `pos` is in the middle of a block.
        let block_start = pos & !3;

        // `subkey` is the key at `block_start`
        let subkey = if let Some(subkey) = self.subkeys.get(&block_start) {
            *subkey
        } else if let Some(prev_subkey) = self.subkeys.get(&(block_start - 4)) {
            MarKeystream::next_subkey(*prev_subkey, self.key)
        } else {
            // This happens if keystream got seeked to a random position.
            // We first find the nearest subkey and then iterate until we get to `block_start`.
            // Since subkeys are in a hashmap, keys are not ordered therefore this is
            // O(N) complexity but should be faster than starting from the beginning
            let positions = self.subkeys.keys();
            let mut nearest_pos_low = 0;
            let mut nearest_pos_high = None;
            for &pos in positions {
                if pos <= block_start && pos > nearest_pos_low {
                    nearest_pos_low = pos;
                }
                if pos > block_start
                    && (nearest_pos_high.is_none() || pos < nearest_pos_high.unwrap())
                {
                    nearest_pos_high = Some(pos);
                }
            }
            assert!(nearest_pos_low % 4 == 0);
            assert!(nearest_pos_high.is_none() || nearest_pos_high.unwrap() % 4 == 0);

            if nearest_pos_high.is_none()
                || nearest_pos_high.unwrap() - block_start > block_start - nearest_pos_low
            {
                let mut subkey = *self.subkeys.get(&nearest_pos_low).unwrap();
                while nearest_pos_low < block_start {
                    subkey = MarKeystream::next_subkey(subkey, self.key);
                    nearest_pos_low += 4;
                    if nearest_pos_low % 0x1000 == 0 {
                        assert!(
                            self.subkeys.insert(nearest_pos_low, subkey).is_none(),
                            "shouldn't happen since we started at the closest subkey"
                        )
                    }
                }
                subkey
            } else {
                let mut nearest_pos_high = nearest_pos_high.unwrap();
                let mut subkey = *self.subkeys.get(&nearest_pos_high).unwrap();
                while nearest_pos_high > block_start {
                    subkey = MarKeystream::prev_subkey(subkey, self.key);
                    nearest_pos_high -= 4;
                    if nearest_pos_high % 0x1000 == 0 {
                        assert!(
                            self.subkeys.insert(nearest_pos_high, subkey).is_none(),
                            "shouldn't happen since we started at the closest subkey"
                        );
                    }
                }
                subkey
            }
        };

        MarKeystreamIterator {
            key: self.key,
            subkey,
            previous_subkey: None,
        }
    }

    fn add_checkpoint(&mut self, pos: u64, subkey: u32) {
        self.subkeys.entry(pos).or_insert(subkey);
    }

    #[inline(always)]
    fn next_subkey(subkey: u32, key: u32) -> u32 {
        key.wrapping_add(subkey).rotate_left(5)
    }

    #[inline(always)]
    fn prev_subkey(subkey: u32, key: u32) -> u32 {
        subkey.rotate_right(5).wrapping_sub(key)
    }
}

#[derive(Clone, Debug)]
struct MarKeystreamIterator {
    key: u32,
    subkey: u32,
    previous_subkey: Option<u32>,
}

impl Iterator for MarKeystreamIterator {
    type Item = [u8; 4];

    fn next(&mut self) -> Option<Self::Item> {
        let block = self.subkey.to_le_bytes();
        self.previous_subkey = Some(self.subkey);
        self.subkey = MarKeystream::next_subkey(self.subkey, self.key);
        Some(block)
    }
}

impl MarKeystreamIterator {
    fn rewind(&mut self) {
        if let Some(prev_subkey) = self.previous_subkey {
            self.subkey = prev_subkey;
            // rewinding past the beginning is possible if we first `next()`ed
            // then `rewind()`ed more than once but eh...
            self.previous_subkey = Some(MarKeystream::prev_subkey(self.subkey, self.key));
        }
    }
}

fn read_file_name<T>(rdr: &mut T) -> Result<(String, Vec<u8>), KArchiveError>
where
    T: BufRead + Seek,
{
    let mut buf = Vec::<u8>::new();
    rdr.read_until(0, &mut buf)?;
    buf.remove(buf.len() - 1);
    Ok((
        String::from_utf8(buf.clone())?
            .trim_start_matches(['.', '\\', '/'])
            .replace('\\', "/")
            .to_string(),
        buf,
    ))
}

pub(crate) fn parse(path: PathBuf) -> Result<KArchive, KArchiveError> {
    // since we are parsing the buffer if it exists, an argument can be made that we should decrypt the contents
    // of the buffer since we would do it in chunks to save memory. is it worth it to actually do so
    // when we mostly aren't going to be seeking anyways?
    let buffer = benchmark(&path)?;
    let mut file = match &buffer {
        Some(buf) => BufReader::new(InternalFile::Buffer(Cursor::new(buf))),
        None => BufReader::new(InternalFile::RealFile(File::open(&path)?)),
    };
    let mut files: HashMap<PathBuf, KFileInfo> = HashMap::new();
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != b"MASMAR0\0" {
        Err(KArchiveError::ParseError(format!(
            "magic number is wrong: {:?}",
            magic
        )))?
    }
    // Number of files is not known until you read...
    loop {
        let mut parse_result = || -> Result<(), KArchiveError> {
            match file.read_u8()? {
                1 => {
                    let (sanitized_name, real_name) = read_file_name(&mut file)?;
                    let size = file.read_u32::<LittleEndian>()? as u64;
                    let offset = file.stream_position()?;
                    file.seek_relative(size as i64)?;
                    let crypted = path.file_name().unwrap().to_str().unwrap().contains("M32");
                    if !crypted {
                        files.insert(
                            sanitized_name.into(),
                            KFileInfo {
                                size,
                                offset,
                                cipher: None,
                            },
                        );
                        Ok(())
                    } else {
                        // derive the key and IV for the cipher here.
                        let mut crc32 = CRCu32::crc32();
                        crc32.digest(&real_name);
                        let iv = crc32.get_crc();
                        let mut crc_x25 = CRCu16::crc16_x25();
                        crc_x25.digest(&real_name);
                        let key = crc_x25.get_crc() as u32 * 3;
                        files.insert(
                            sanitized_name.into(),
                            KFileInfo {
                                size,
                                offset,
                                cipher: Some(MarCipher::new(key, iv, size)),
                            },
                        );
                        Ok(())
                    }
                }
                2 => {
                    // This is for directories. we read the filename but do nothing with it...
                    read_file_name(&mut file)?;
                    Ok(())
                }
                0xFF => Err(KArchiveError::Other("Finished parsing")),
                _ => unreachable!("Invalid mar"),
            }
        };
        match parse_result() {
            Ok(()) => {} // keep iterating
            Err(KArchiveError::Other(_)) => break,
            Err(e) => {
                eprintln!("k_archives: Error in archive parsing: {}", e);
                eprintln!("k_archives: Continuing with {} files parsed", files.len());
                break;
            }
        }
    }
    Ok(KArchive::new(path, files, buffer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use indicatif::ParallelProgressIterator;
    use rand::{distributions::Uniform, Rng};
    use std::io::Cursor;

    #[test]
    fn test_filename() {
        let cursor = Cursor::new(vec![
            47, 100, 101, 118, 47, 114, 97, 119, 47, 110, 101, 119, 100, 97, 116, 97, 47, 70, 105,
            108, 101, 76, 105, 115, 116, 46, 100, 97, 116, 0,
        ]);
        let mut filename = BufReader::new(cursor);
        assert_eq!(
            read_file_name(&mut filename).unwrap().0,
            "dev/raw/newdata/FileList.dat"
        )
    }
    // reference implementation to verify our chunked version against...
    fn reference_crypt(key: u32, iv: u32, data: &mut [u8]) {
        let mut idx = 0;
        let mut j = 0;
        let mut k = iv;
        // let k2 = 0;
        while idx < data.len() {
            let k2 = key.wrapping_add(k);
            k = (k2 << 5) | (k2 >> 27);
            if idx + 4 > data.len() {
                break;
            }
            data[idx] ^= (k & 0xff) as u8;
            data[idx + 1] ^= ((k >> 8) & 0xff) as u8;
            data[idx + 2] ^= ((k >> 16) & 0xff) as u8;
            data[idx + 3] ^= ((k >> 24) & 0xff) as u8;
            idx += 4;
        }

        while idx + j < data.len() {
            data[idx] ^= ((k >> (8 * j)) & 0xff) as u8;
            j += 1;
        }
    }

    // These tests must all pass to be considered a valid implementation.
    // Any proposed changes to the underlying cipher must be able to handle this
    #[test]
    fn test_cipher_n() {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0_u8, 0xFF_u8);
        // generate a completely random buffer for testing both ciphers
        let data: Vec<u8> = (0..100).map(|_| rng.sample(range)).collect();
        let mut buf_chunked = data.clone();
        let mut buf_reference = data.clone();
        let key = rng.gen_range(0_u32..0xFFFFFFFF_u32);
        let iv = rng.gen_range(0_u32..0xFFFFFFFF_u32);
        reference_crypt(key, iv, &mut buf_reference);
        let mut cipher = MarCipher::new(key, iv, data.len() as u64);
        for i in 0..data.len() {
            cipher.crypt(&mut buf_chunked[i..i + 1])
        }
        assert_eq!(buf_chunked, buf_reference);
    }

    #[test]
    fn test_cipher_nplus1() {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0_u8, 0xFF_u8);
        // generate a completely random buffer for testing both ciphers
        let data: Vec<u8> = (0..101).map(|_| rng.sample(range)).collect();
        let mut buf_chunked = data.clone();
        let mut buf_reference = data.clone();
        let key = rng.gen_range(0_u32..0xFFFFFFFF_u32);
        let iv = rng.gen_range(0_u32..0xFFFFFFFF_u32);
        reference_crypt(key, iv, &mut buf_reference);
        let mut cipher = MarCipher::new(key, iv, data.len() as u64);
        for i in 0..data.len() {
            cipher.crypt(&mut buf_chunked[i..i + 1])
        }
        assert_eq!(buf_chunked, buf_reference);
    }

    #[test]
    fn test_cipher_nplus2() {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0_u8, 0xFF_u8);
        // generate a completely random buffer for testing both ciphers
        let data: Vec<u8> = (0..102).map(|_| rng.sample(range)).collect();
        let mut buf_chunked = data.clone();
        let mut buf_reference = data.clone();
        let key = rng.gen_range(0_u32..0xFFFFFFFF_u32);
        let iv = rng.gen_range(0_u32..0xFFFFFFFF_u32);
        reference_crypt(key, iv, &mut buf_reference);
        let mut cipher = MarCipher::new(key, iv, data.len() as u64);
        for i in 0..data.len() {
            cipher.crypt(&mut buf_chunked[i..i + 1])
        }
        assert_eq!(buf_chunked, buf_reference);
    }

    #[test]
    fn test_cipher_nplus3() {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0_u8, 0xFF_u8);
        // generate a completely random buffer for testing both ciphers
        let data: Vec<u8> = (0..103).map(|_| rng.sample(range)).collect();
        let mut buf_chunked = data.clone();
        let mut buf_reference = data.clone();
        let key = rng.gen_range(0_u32..0xFFFFFFFF_u32);
        let iv = rng.gen_range(0_u32..0xFFFFFFFF_u32);
        reference_crypt(key, iv, &mut buf_reference);
        let mut cipher = MarCipher::new(key, iv, data.len() as u64);
        for i in 0..data.len() {
            cipher.crypt(&mut buf_chunked[i..i + 1])
        }
        assert_eq!(buf_chunked, buf_reference);
    }

    #[test]
    fn test_keystream() {
        let mut rng = rand::thread_rng();
        let key: u32 = rng.gen();
        let iv: u32 = rng.gen();
        let mut keystream = MarKeystream::new(key, iv).get_keystream(0);
        let mut ref_subkey = iv;
        for _ in 0..0x100 {
            let subkey = keystream.next().unwrap();
            let temp = key.wrapping_add(ref_subkey);
            ref_subkey = (temp << 5) | (temp >> 27);
            assert_eq!(subkey[0], (ref_subkey & 0xFF) as u8);
            assert_eq!(subkey[1], ((ref_subkey >> 8) & 0xFF) as u8);
            assert_eq!(subkey[2], ((ref_subkey >> 16) & 0xFF) as u8);
            assert_eq!(subkey[3], ((ref_subkey >> 24) & 0xFF) as u8);
        }
    }

    #[test]
    fn test_reverse() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let key: u32 = rng.gen();
            let iv: u32 = rng.gen();
            let mut subkey = iv;
            for i in 0..0x100 {
                let next_subkey = MarKeystream::next_subkey(subkey, key);
                assert_eq!(
                    subkey,
                    MarKeystream::prev_subkey(next_subkey, key),
                    "failed @ key: {key}, iv: {iv}, subkey: {subkey}, iteration: {i}"
                );
                subkey = next_subkey;
            }
        }
    }

    #[test]
    fn test_seek() {
        let mut rng = rand::thread_rng();
        let key: u32 = rng.gen();
        let iv: u32 = rng.gen();
        let data_size = rng.gen_range(0x2000..0x10_000);
        let data: Vec<u8> = (0..data_size).map(|_| rng.gen::<u8>()).collect();
        let mut buf_reference = data.clone();
        reference_crypt(key, iv, &mut buf_reference);
        let mut cipher = MarCipher::new(key, iv, data_size as u64);

        for i in 0..100 {
            let mut buf_test = data.clone();
            let pos = rng.gen_range(0..(data_size - 0x10)) as usize;
            assert_eq!(
                cipher.seek(std::io::SeekFrom::Start(pos as u64)).unwrap(),
                pos as u64
            );
            cipher.crypt(&mut buf_test[pos..(pos + 0x10)]);
            assert_eq!(
                buf_test[pos..(pos + 0x10)],
                buf_reference[pos..(pos + 0x10)],
                "failed @ key: {key}, iv: {iv}, iteration: {i}, pos: {pos}"
            );
        }
    }

    #[test]
    #[ignore] // this test is slow
    fn fuzz_cipher() {
        use rayon::prelude::*;

        use indicatif::{ProgressBar, ProgressStyle};
        use rand::SeedableRng;

        let mut seeder = rand::thread_rng();
        let seeds: Vec<(u64, u64)> = (0..100_000).map(|i| (i, seeder.gen())).collect();
        let progress = ProgressBar::new(seeds.len() as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:14} {msg}",
                )
                .progress_chars("##-"),
        );

        seeds
            .par_iter()
            .progress_with(progress.clone())
            .for_each(|&(index, seed)| {
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
                let data_len: usize = rng.gen_range(1..0x1_000);

                let data_rng_seed: u64 = rng.gen();
                let mut data_rng = rand::rngs::StdRng::seed_from_u64(data_rng_seed);
                let data: Vec<u8> = (0..data_len).map(|_| data_rng.gen::<u8>()).collect();

                let mut buf_chunked = data.clone();
                let mut buf_reference = data.clone();
                let key = rng.gen_range(0_u32..0xFFFFFFFF_u32);
                let iv = rng.gen_range(0_u32..0xFFFFFFFF_u32);
                reference_crypt(key, iv, &mut buf_reference);
                let mut cipher = MarCipher::new(key, iv, data.len() as u64);

                let mut data_index = 0;
                while data_index < data.len() {
                    let to_read = usize::min(data.len() - data_index, rng.gen_range(1..0x100));
                    cipher.crypt(&mut buf_chunked[data_index..data_index + to_read]);
                    data_index += to_read;
                }
                if buf_chunked != buf_reference {
                    progress.println(format!("Failed @{index}: seed: {seed}, len: {data_len}, data_seed: {data_rng_seed}, key: {key}, iv: {iv}"))
                }
                assert_eq!(buf_chunked, buf_reference);
            });
    }
}
