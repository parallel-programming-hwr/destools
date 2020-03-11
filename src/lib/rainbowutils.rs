use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use rand::AsByteSliceMut;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::io::{Error, ErrorKind};

pub const BDF_HDR: &[u8; 11] = b"BDF\x01RAINBOW";
pub const NULL_BYTES: &[u8; 4] = &[0u8; 4];

pub struct BinaryDictionaryFile {
    name: String,
    reader: BufReader<File>,
    metadata: Option<MetaChunk>,
}

#[derive(Debug, Clone)]
pub struct GenericChunk {
    length: u32,
    name: String,
    data: Vec<u8>,
    crc: u32,
}

#[derive(Debug, Clone)]
pub struct MetaChunk {
    chunk_count: u32,
    entries_per_chunk: u32,
    entry_count: u32,
    compression_method: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HashEntry {
    id: u32,
    output_length: u32,
    name: String,
}

#[derive(Debug, Clone)]
pub struct DataEntry {
    plain: String,
    hashes: HashMap<String, Vec<u8>>,
}

impl BinaryDictionaryFile {
    fn new(reader: BufReader<File>) -> Self {
        Self {
            name: "".to_string(),
            metadata: None,
            reader,
        }
    }

    fn read_metadata(&mut self) -> Result<MetaChunk, Error> {
        if !self.validate_header() {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid BDF Header!"));
        }
        let meta_chunk = self.next_chunk().as_meta_chunk();
        self.metadata = Some(meta_chunk.clone());

        Ok(meta_chunk)
    }

    fn validate_header(&mut self) -> bool {
        let mut header = [0u8; 11];
        let _ = self.reader.read(&mut header);

        header == BDF_HDR.as_ref()
    }

    fn next_chunk(&mut self) -> GenericChunk {
        let mut length_raw = [0u8; 4];
        let _ = self.reader.read(&mut length_raw);
        let length = BigEndian::read_u32(&mut length_raw);
        let mut name_raw = [0u8; 4];
        let _ = self.reader.read(&mut name_raw);
        let name =
            String::from_utf8(name_raw.to_vec()).expect("Failed to parse chunk name to string!");
        let mut data = vec![0u8; length as usize];
        let _ = self.reader.read(&mut data);
        let mut crc_raw = [0u8; 4];
        let _ = self.reader.read(&mut crc_raw);
        let crc = BigEndian::read_u32(&mut crc_raw);

        GenericChunk {
            length,
            name,
            data,
            crc,
        }
    }
}

impl GenericChunk {
    fn as_meta_chunk(&self) -> MetaChunk {
        let mut chunk_count_raw = self.data[0..4].to_vec();
        let mut entries_per_chunk = self.data[4..8].to_vec();
        let mut total_number_of_entries = self.data[8..12].to_vec();
        let mut compression_method_raw = self.data[12..16].to_vec();
        let chunk_count = BigEndian::read_u32(&mut chunk_count_raw);
        let entries_per_chunk = BigEndian::read_u32(&mut entries_per_chunk);
        let entry_count = BigEndian::read_u32(&mut total_number_of_entries);
        let compression_method = if &compression_method_raw != NULL_BYTES {
            Some(
                String::from_utf8(compression_method_raw.to_vec())
                    .expect("Failed to parse compression method from meta string"),
            )
        } else {
            None
        };

        MetaChunk {
            chunk_count,
            entries_per_chunk,
            entry_count,
            compression_method,
        }
    }
}
