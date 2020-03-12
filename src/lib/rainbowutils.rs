use byteorder::{BigEndian, ByteOrder};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{BufReader, Read};
use std::io::{Error, ErrorKind};

pub const BDF_HDR: &[u8; 11] = b"BDF\x01RAINBOW";
pub const NULL_BYTES: &[u8; 4] = &[0u8; 4];
pub const META_CHUNK_NAME: &str = "META";
pub const HTBL_CHUNK_NAME: &str = "HTBL";
pub const DTBL_CHUNK_NAME: &str = "DTBL";

pub struct BinaryDictionaryFile {
    name: String,
    reader: BufReader<File>,
    metadata: Option<MetaChunk>,
    lookup_table: Option<HashLookupTable>,
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
pub struct HashLookupTable {
    entries: HashMap<u32, HashEntry>,
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
    pub fn new(reader: BufReader<File>) -> Self {
        Self {
            name: "".to_string(),
            metadata: None,
            lookup_table: None,
            reader,
        }
    }

    pub fn read_metadata(&mut self) -> Result<&MetaChunk, Error> {
        if !self.validate_header() {
            return Err(Error::new(ErrorKind::InvalidData, "invalid BDF Header"));
        }
        let meta_chunk: MetaChunk = self.next_chunk()?.try_into()?;
        self.metadata = Some(meta_chunk);

        if let Some(chunk) = &self.metadata {
            Ok(&chunk)
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "Failed to read self assigned metadata.",
            ))
        }
    }

    pub fn read_lookup_table(&mut self) -> Result<&HashLookupTable, Error> {
        match &self.metadata {
            None => self.read_metadata()?,
            Some(t) => t,
        };
        let lookup_table: HashLookupTable = self.next_chunk()?.try_into()?;
        self.lookup_table = Some(lookup_table);

        if let Some(chunk) = &self.lookup_table {
            Ok(&chunk)
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "failed to read self assigned chunk",
            ))
        }
    }

    fn validate_header(&mut self) -> bool {
        let mut header = [0u8; 11];
        let _ = self.reader.read(&mut header);

        header == BDF_HDR.as_ref()
    }

    /// Returns the next chunk if one is available.
    pub fn next_chunk(&mut self) -> Result<GenericChunk, Error> {
        let mut length_raw = [0u8; 4];
        let _ = self.reader.read_exact(&mut length_raw)?;
        let length = BigEndian::read_u32(&mut length_raw);
        let mut name_raw = [0u8; 4];
        let _ = self.reader.read_exact(&mut name_raw)?;
        let name = String::from_utf8(name_raw.to_vec()).expect("Failed to parse name string.");
        let mut data = vec![0u8; length as usize];
        let _ = self.reader.read_exact(&mut data)?;
        let mut crc_raw = [0u8; 4];
        let _ = self.reader.read_exact(&mut crc_raw)?;
        let crc = BigEndian::read_u32(&mut crc_raw);

        Ok(GenericChunk {
            length,
            name,
            data,
            crc,
        })
    }
}

impl TryFrom<GenericChunk> for MetaChunk {
    type Error = Error;

    fn try_from(chunk: GenericChunk) -> Result<MetaChunk, Error> {
        if &chunk.name != HTBL_CHUNK_NAME {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "chunk name doesn't match",
            ));
        }
        if chunk.data.len() < 16 {
            return Err(Error::new(ErrorKind::InvalidData, "invalid chunk data"));
        }
        let chunk_count_raw = &chunk.data[0..4];
        let entries_per_chunk = &chunk.data[4..8];
        let total_number_of_entries = &chunk.data[8..12];
        let compression_method_raw = chunk.data[12..16].to_vec();
        let chunk_count = BigEndian::read_u32(chunk_count_raw);
        let entries_per_chunk = BigEndian::read_u32(entries_per_chunk);
        let entry_count = BigEndian::read_u32(total_number_of_entries);
        let compression_method = if &compression_method_raw != NULL_BYTES {
            Some(
                String::from_utf8(compression_method_raw)
                    .expect("Failed to parse compression method name!"),
            )
        } else {
            None
        };

        Ok(MetaChunk {
            chunk_count,
            entries_per_chunk,
            entry_count,
            compression_method,
        })
    }
}

impl HashLookupTable {
    pub fn get_entry(&self, id: u32) -> Option<&HashEntry> {
        self.entries.get(&id)
    }
}

impl TryFrom<GenericChunk> for HashLookupTable {
    type Error = Error;

    fn try_from(chunk: GenericChunk) -> Result<HashLookupTable, Error> {
        if &chunk.name != HTBL_CHUNK_NAME {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "chunk name doesn't match",
            ));
        }
        let mut hash_entries: HashMap<u32, HashEntry> = HashMap::new();
        let mut position = 0;
        while chunk.data.len() > (position + 12) {
            let id_raw = &chunk.data[position..position + 4];
            position += 4;
            let output_length_raw = &chunk.data[position..position + 4];
            position += 4;
            let name_length_raw = &chunk.data[position..position + 4];
            position += 4;
            let id = BigEndian::read_u32(id_raw);
            let output_length = BigEndian::read_u32(output_length_raw);
            let name_length = BigEndian::read_u32(name_length_raw);
            let name_raw = &chunk.data[position..position + name_length as usize];
            let name =
                String::from_utf8(name_raw.to_vec()).expect("Failed to parse hash function name!");
            hash_entries.insert(
                id,
                HashEntry {
                    id,
                    output_length,
                    name,
                },
            );
        }
        Ok(HashLookupTable {
            entries: hash_entries,
        })
    }
}
