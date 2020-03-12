use byteorder::{BigEndian, ByteOrder};
use crc::crc32;
use rayon::prelude::*;
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
    pub entries: HashMap<u32, HashEntry>,
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
            metadata: None,
            lookup_table: None,
            reader,
        }
    }

    /// Verifies the header of the file and reads and stores the metadata
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

    /// Reads the lookup table of the file.
    /// This function should be called after the read_metadata function was called
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

impl GenericChunk {
    pub fn serialize(&mut self) -> Vec<u8> {
        let mut serialized: Vec<u8> = Vec::new();
        let mut length_raw = [0u8; 4];
        BigEndian::write_u32(&mut length_raw, self.length);
        serialized.append(&mut length_raw.to_vec());
        let name_raw = self.name.as_bytes();
        serialized.append(&mut name_raw.to_vec());
        serialized.append(&mut self.data);
        let mut crc_raw = [0u8; 4];
        BigEndian::write_u32(&mut crc_raw, self.crc);
        serialized.append(&mut crc_raw.to_vec());

        serialized
    }

    /// Returns the data entries of the chunk
    pub fn data_entries(
        &mut self,
        lookup_table: &HashLookupTable,
    ) -> Result<Vec<DataEntry>, Error> {
        let mut entries: Vec<DataEntry> = Vec::new();
        let mut position = 0;
        while self.data.len() > position {
            let entry_length_raw = &self.data[position..position + 4];
            position += 4;
            let entry_length = BigEndian::read_u32(entry_length_raw);
            let entry_end = position + entry_length as usize;
            let pw_length_raw = &self.data[position..position + 4];
            position += 4;
            let pw_length = BigEndian::read_u32(pw_length_raw);
            let pw_plain_raw = &self.data[position..position + pw_length as usize];
            position += pw_length as usize;
            let pw_plain = String::from_utf8(pw_plain_raw.to_vec())
                .expect("failed to parse plain password string");
            let mut hash_values: HashMap<String, Vec<u8>> = HashMap::new();
            while position < entry_end {
                let entry_id_raw = &self.data[position..position + 4];
                position += 4;
                let entry_id = BigEndian::read_u32(entry_id_raw);
                if let Some(hash_entry) = lookup_table.entries.get(&entry_id) {
                    let hash = &self.data[position..position + hash_entry.output_length as usize];
                    position += hash_entry.output_length as usize;
                    hash_values.insert(hash_entry.name.clone(), hash.to_vec());
                }
            }
            entries.push(DataEntry {
                plain: pw_plain,
                hashes: hash_values,
            })
        }

        Ok(entries)
    }

    /// Constructs the chunk from a Vec of Data entries and a hash lookup table
    pub fn from_data_entries(
        entries: Vec<DataEntry>,
        lookup_table: HashLookupTable,
    ) -> GenericChunk {
        let mut serialized_data: Vec<u8> = Vec::new();
        let serialized_entries: Vec<Vec<u8>> = entries
            .par_iter()
            .map(|entry: &DataEntry| entry.serialize(lookup_table.clone()))
            .collect();
        serialized_entries.iter().for_each(|entry| {
            serialized_data.append(&mut entry.clone());
        });
        let crc_sum = crc32::checksum_ieee(serialized_data.as_slice());

        GenericChunk {
            length: serialized_data.len() as u32,
            name: DTBL_CHUNK_NAME.to_string(),
            data: serialized_data,
            crc: crc_sum,
        }
    }
}

impl From<MetaChunk> for GenericChunk {
    fn from(chunk: MetaChunk) -> GenericChunk {
        let serialized_data = chunk.serialize();
        let crc_sum = crc32::checksum_ieee(serialized_data.as_slice());

        GenericChunk {
            length: serialized_data.len() as u32,
            name: META_CHUNK_NAME.to_string(),
            data: serialized_data,
            crc: crc_sum,
        }
    }
}

impl From<HashLookupTable> for GenericChunk {
    fn from(chunk: HashLookupTable) -> GenericChunk {
        let serialized_data = chunk.serialize();
        let crc_sum = crc32::checksum_ieee(serialized_data.as_slice());

        GenericChunk {
            length: serialized_data.len() as u32,
            name: HTBL_CHUNK_NAME.to_string(),
            data: serialized_data,
            crc: crc_sum,
        }
    }
}

impl MetaChunk {
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data: Vec<u8> = Vec::new();
        let mut chunk_count_raw = [0u8; 4];
        BigEndian::write_u32(&mut chunk_count_raw, self.chunk_count);
        serialized_data.append(&mut chunk_count_raw.to_vec());
        let mut entries_pc_raw = [0u8; 4];
        BigEndian::write_u32(&mut entries_pc_raw, self.entries_per_chunk);
        serialized_data.append(&mut entries_pc_raw.to_vec());
        let mut total_entries_raw = [0u8; 4];
        BigEndian::write_u32(&mut total_entries_raw, self.entry_count);
        serialized_data.append(&mut total_entries_raw.to_vec());
        let mut compression_method = self.compression_method.clone();
        if let Some(method) = &mut compression_method {
            serialized_data.append(&mut method.clone().into_bytes());
        } else {
            serialized_data.append(&mut vec![0, 0, 0, 0]);
        }

        serialized_data
    }
}

impl TryFrom<GenericChunk> for MetaChunk {
    type Error = Error;

    fn try_from(chunk: GenericChunk) -> Result<MetaChunk, Error> {
        if &chunk.name != META_CHUNK_NAME {
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
    pub fn get_entry(&self, name: &String) -> Option<(&u32, &HashEntry)> {
        self.entries.iter().find(|(_, entry)| entry.name == *name)
    }

    /// Serializes the lookup table into a vector of bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_full: Vec<u8> = Vec::new();
        for (_, entry) in &self.entries {
            serialized_full.append(entry.serialize().as_mut())
        }

        serialized_full
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

impl HashEntry {
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized: Vec<u8> = Vec::new();
        let mut id_raw = [0u8; 4];
        BigEndian::write_u32(&mut id_raw, self.id);
        serialized.append(&mut id_raw.to_vec());
        let mut output_length_raw = [0u8; 4];
        BigEndian::write_u32(&mut output_length_raw, self.output_length);
        serialized.append(&mut output_length_raw.to_vec());
        let mut name_raw = self.name.clone().into_bytes();
        let mut name_length_raw = [0u8; 4];
        BigEndian::write_u32(&mut name_length_raw, name_raw.len() as u32);
        serialized.append(&mut name_length_raw.to_vec());
        serialized.append(&mut name_raw);

        serialized
    }
}

impl DataEntry {
    pub fn serialize(&self, lookup_table: HashLookupTable) -> Vec<u8> {
        let mut pw_plain_raw = self.plain.clone().into_bytes();
        let mut pw_length_raw = [0u8; 4];
        BigEndian::write_u32(&mut pw_length_raw, pw_plain_raw.len() as u32);
        let mut hash_data: Vec<u8> = Vec::new();
        for (name, value) in &self.hashes {
            if let Some((id, _)) = lookup_table.get_entry(&name) {
                let mut id_raw = [0u8; 4];
                BigEndian::write_u32(&mut id_raw, *id);
                hash_data.append(&mut id_raw.to_vec());
                hash_data.append(&mut value.clone())
            }
        }

        let mut length_total_raw = [0u8; 4];
        BigEndian::write_u32(
            &mut length_total_raw,
            4 + pw_plain_raw.len() as u32 + hash_data.len() as u32,
        );
        let mut serialized_data: Vec<u8> = Vec::new();
        serialized_data.append(&mut length_total_raw.to_vec());
        serialized_data.append(&mut pw_length_raw.to_vec());
        serialized_data.append(&mut pw_plain_raw);
        serialized_data.append(&mut hash_data);

        serialized_data
    }
}
