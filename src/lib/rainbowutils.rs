use byteorder::{BigEndian, ByteOrder};
use crc::crc32;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::io::{Error, ErrorKind};
use xz2::read::{XzDecoder, XzEncoder};

pub const LZMA: &str = "lzma";

pub const BDF_HDR: &[u8; 11] = b"BDF\x01RAINBOW";
pub const NULL_BYTES: &[u8; 4] = &[0u8; 4];
pub const META_CHUNK_NAME: &str = "META";
pub const HTBL_CHUNK_NAME: &str = "HTBL";
pub const DTBL_CHUNK_NAME: &str = "DTBL";
pub const ENTRIES_PER_CHUNK: u32 = 100_000;

pub struct BDFReader {
    reader: BufReader<File>,
    pub metadata: Option<MetaChunk>,
    pub lookup_table: Option<HashLookupTable>,
    compressed: bool,
}

pub struct BDFWriter {
    writer: BufWriter<File>,
    metadata: MetaChunk,
    lookup_table: HashLookupTable,
    data_entries: Vec<DataEntry>,
    head_written: bool,
    compressed: bool,
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
    pub chunk_count: u32,
    entries_per_chunk: u32,
    pub entry_count: u64,
    pub compression_method: Option<String>,
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
    pub plain: String,
    hashes: HashMap<String, Vec<u8>>,
}

impl BDFWriter {
    pub fn new(writer: BufWriter<File>, entry_count: u64, compress: bool) -> Self {
        Self {
            metadata: MetaChunk::new(entry_count, ENTRIES_PER_CHUNK, compress),
            lookup_table: HashLookupTable::new(HashMap::new()),
            data_entries: Vec::new(),
            writer,
            head_written: false,
            compressed: compress,
        }
    }

    /// Adds an entry to the hash lookup table
    /// If the lookup table has already been written to the file, an error ris returned
    pub fn add_lookup_entry(&mut self, mut entry: HashEntry) -> Result<u32, Error> {
        if self.head_written {
            return Err(Error::new(
                ErrorKind::Other,
                "the head has already been written",
            ));
        }
        let id = self.lookup_table.entries.len() as u32;
        entry.id = id;
        self.lookup_table.entries.insert(id, entry);

        Ok(id)
    }

    /// Adds a data entry to the file.
    /// If the number of entries per chunk is reached,
    /// the data will be written to the file
    pub fn add_data_entry(&mut self, data_entry: DataEntry) -> Result<(), Error> {
        self.data_entries.push(data_entry);
        if self.data_entries.len() >= ENTRIES_PER_CHUNK as usize {
            self.flush()?;
        }

        Ok(())
    }

    /// Writes the data to the file
    pub fn flush(&mut self) -> Result<(), Error> {
        if !self.head_written {
            self.writer.write(BDF_HDR)?;
            let mut generic_meta = GenericChunk::from(&self.metadata);
            self.writer.write(generic_meta.serialize().as_slice())?;
            let mut generic_lookup = GenericChunk::from(&self.lookup_table);
            self.writer.write(generic_lookup.serialize().as_slice())?;
            self.head_written = true;
        }
        let mut data_chunk =
            GenericChunk::from_data_entries(&self.data_entries, &self.lookup_table);
        if self.compressed {
            data_chunk.compress()?;
        }
        let data = data_chunk.serialize();
        self.writer.write(data.as_slice())?;
        self.data_entries = Vec::new();

        Ok(())
    }

    pub fn flush_writer(&mut self) -> Result<(), Error> {
        self.writer.flush()
    }
}

impl BDFReader {
    pub fn new(reader: BufReader<File>) -> Self {
        Self {
            metadata: None,
            lookup_table: None,
            reader,
            compressed: false,
        }
    }

    /// Verifies the header of the file and reads and stores the metadata
    pub fn read_metadata(&mut self) -> Result<&MetaChunk, Error> {
        if !self.validate_header() {
            return Err(Error::new(ErrorKind::InvalidData, "invalid BDF Header"));
        }
        let meta_chunk: MetaChunk = self.next_chunk()?.try_into()?;
        if let Some(method) = &meta_chunk.compression_method {
            if *method == LZMA.to_string() {
                self.compressed = true;
            } else {
                return Err(Error::new(
                    ErrorKind::Other,
                    "unsupported compression method",
                ));
            }
        }
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

    /// Validates the header of the file
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
        let mut gen_chunk = GenericChunk {
            length,
            name,
            data,
            crc,
        };
        if gen_chunk.name == DTBL_CHUNK_NAME.to_string() && self.compressed {
            gen_chunk.decompress()?;
        }

        Ok(gen_chunk)
    }
}

impl GenericChunk {
    /// Serializes the chunk to a vector of bytes
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
        if self.name == HTBL_CHUNK_NAME.to_string() {
            return Err(Error::new(ErrorKind::Other, "this is not a data chunk"));
        }
        let mut entries: Vec<DataEntry> = Vec::new();
        let mut position = 0;
        while self.data.len() > (position + 8) {
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
                .map_err(|err| {
                    format!(
                        "failed to parse plain password string ({}-{}): {:?}",
                        position,
                        position + pw_length as usize,
                        err
                    )
                })
                .unwrap();
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
        entries: &Vec<DataEntry>,
        lookup_table: &HashLookupTable,
    ) -> GenericChunk {
        let mut serialized_data: Vec<u8> = Vec::new();
        entries.iter().for_each(|entry| {
            serialized_data.append(&mut entry.serialize(&lookup_table));
        });
        let crc_sum = crc32::checksum_ieee(serialized_data.as_slice());

        GenericChunk {
            length: serialized_data.len() as u32,
            name: DTBL_CHUNK_NAME.to_string(),
            data: serialized_data,
            crc: crc_sum,
        }
    }

    pub fn compress(&mut self) -> Result<(), Error> {
        let data = self.data.as_slice();
        let mut compressor = XzEncoder::new(data, 6);
        let mut compressed: Vec<u8> = Vec::new();
        compressor.read_to_end(&mut compressed)?;
        self.length = compressed.len() as u32;
        self.data = compressed;

        Ok(())
    }

    pub fn decompress(&mut self) -> Result<(), Error> {
        let data = self.data.as_slice();
        let mut decompressor = XzDecoder::new(data);
        let mut decompressed: Vec<u8> = Vec::new();
        decompressor.read_to_end(&mut decompressed)?;
        let crc = crc32::checksum_ieee(decompressed.as_slice());
        if crc != self.crc {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "the crc doesn't match the decrypted data",
            ));
        }
        self.length = decompressed.len() as u32;
        self.data = decompressed;

        Ok(())
    }
}

impl From<&MetaChunk> for GenericChunk {
    fn from(chunk: &MetaChunk) -> GenericChunk {
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

impl From<&HashLookupTable> for GenericChunk {
    fn from(chunk: &HashLookupTable) -> GenericChunk {
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
    /// Creates a new meta chunk
    pub fn new(entry_count: u64, entries_per_chunk: u32, compress: bool) -> Self {
        let compression_method = if compress {
            Some(LZMA.to_string())
        } else {
            None
        };
        let chunk_count = (entry_count as f64 / entries_per_chunk as f64).ceil() as u32;

        Self {
            chunk_count,
            entry_count,
            entries_per_chunk,
            compression_method,
        }
    }

    /// Serializes the chunk into bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut serialized_data: Vec<u8> = Vec::new();
        let mut chunk_count_raw = [0u8; 4];
        BigEndian::write_u32(&mut chunk_count_raw, self.chunk_count);
        serialized_data.append(&mut chunk_count_raw.to_vec());
        let mut entries_pc_raw = [0u8; 4];
        BigEndian::write_u32(&mut entries_pc_raw, self.entries_per_chunk);
        serialized_data.append(&mut entries_pc_raw.to_vec());
        let mut total_entries_raw = [0u8; 8];
        BigEndian::write_u64(&mut total_entries_raw, self.entry_count);
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
        if chunk.data.len() < 20 {
            return Err(Error::new(ErrorKind::InvalidData, "invalid chunk data"));
        }
        let chunk_count_raw = &chunk.data[0..4];
        let entries_per_chunk = &chunk.data[4..8];
        let total_number_of_entries = &chunk.data[8..16];
        let compression_method_raw = chunk.data[16..20].to_vec();
        let chunk_count = BigEndian::read_u32(chunk_count_raw);
        let entries_per_chunk = BigEndian::read_u32(entries_per_chunk);
        let entry_count = BigEndian::read_u64(total_number_of_entries);
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
    pub fn new(entries: HashMap<u32, HashEntry>) -> Self {
        Self { entries }
    }

    /// Returns an entry by the name of the hash function
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
    pub fn new(name: String, output_length: u32) -> Self {
        Self {
            id: 0,
            name,
            output_length,
        }
    }

    /// Serializes the entry to a vector of bytes
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
    pub fn new(plain: String) -> Self {
        Self {
            hashes: HashMap::new(),
            plain,
        }
    }

    /// Adds a hash to the hash values
    pub fn add_hash_value(&mut self, name: String, value: Vec<u8>) {
        self.hashes.insert(name, value);
    }

    /// Returns the hash value for a given name of a hash function
    pub fn get_hash_value(&self, name: String) -> Option<&Vec<u8>> {
        self.hashes.get(&name)
    }

    /// Serializes the entry to a vector of bytes
    pub fn serialize(&self, lookup_table: &HashLookupTable) -> Vec<u8> {
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
