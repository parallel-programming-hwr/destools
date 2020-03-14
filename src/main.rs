pub mod lib;

use crate::lib::crypt::{
    decrypt_brute_brute_force, decrypt_data, decrypt_with_dictionary, encrypt_data,
};
use crate::lib::hash::{create_key, sha256, sha_checksum};
use crate::lib::timing::TimeTaker;
use bdf::chunks::{DataEntry, HashEntry, HashLookupTable};
use bdf::io::{BDFReader, BDFWriter};
use pbr::ProgressBar;
use rayon::prelude::*;
use rayon::str;
use regex::Regex;
use rpassword;
use rpassword::read_password_from_tty;
use spinners::{Spinner, Spinners};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::sync::mpsc::sync_channel;
use std::thread;
use std::time::Duration;
use structopt::StructOpt;

#[derive(StructOpt, Clone)]
#[structopt(name = "destools", version = "1.0", author = "Julius R.")]
struct Opts {
    #[structopt(subcommand)]
    subcmd: SubCommand,
}

#[derive(StructOpt, Clone)]
enum SubCommand {
    /// Encrypt a file with des
    #[structopt(name = "encrypt")]
    Encrypt(Encrypt),

    /// Decrypt a DES encoded file
    #[structopt(name = "decrypt")]
    Decrypt(Decrypt),

    /// Create a dictionary rainbow-table from a txt file
    #[structopt(name = "create-dictionary")]
    CreateDictionary(CreateDictionary),
}

#[derive(StructOpt, Clone)]
struct Encrypt {
    /// The input file
    #[structopt(short = "i", long = "input", default_value = "input.txt")]
    input: String,

    /// The output file
    #[structopt(short = "o", long = "output", default_value = "output.des")]
    output: String,

    /// The file for the checksum.
    #[structopt(long = "checksum-file")]
    output_checksum: Option<String>,
}

#[derive(StructOpt, Clone)]
struct Decrypt {
    /// The input file
    #[structopt(short = "i", long = "input", default_value = "input.des")]
    input: String,

    /// The output file
    #[structopt(short = "o", long = "output", default_value = "output.txt")]
    output: String,

    /// The file for the checksum.
    #[structopt(long = "checksum-file")]
    input_checksum: Option<String>,

    /// A dictionary file containing a list of passwords
    /// The file needs to be in a csv format with calculated password hashes.
    /// The hashes can be calculated with the create-dictionary subcommand from a txt file.
    #[structopt(short = "d", long = "dictionary")]
    dictionary: Option<String>,
}

#[derive(StructOpt, Clone)]
struct CreateDictionary {
    /// The input dictionary file.
    #[structopt(short = "i", long = "input", default_value = "passwords.txt")]
    input: String,

    /// The output dictionary file
    #[structopt(short = "o", long = "output", default_value = "dictionary.bdf")]
    output: String,

    /// The compression level of the dictionary file from 1 to 9
    /// 0 means no compression
    #[structopt(short = "c", long = "compression-level", default_value = "0")]
    compress: u32,

    /// The number of password entries per chunk.
    #[structopt(long = "entries-per-chunk", default_value = "100000")]
    entries_per_chunk: u32,
}

fn main() {
    let opts: Opts = Opts::from_args();
    match (opts.clone()).subcmd {
        SubCommand::Encrypt(args) => encrypt(&opts, &args),
        SubCommand::Decrypt(args) => decrypt(&opts, &args),
        SubCommand::CreateDictionary(args) => create_dictionary(&opts, &args),
    }
}

/// Encrypts a file with des
fn encrypt(_opts: &Opts, args: &Encrypt) {
    let input: String = (*args.input).parse().unwrap();
    let output: String = (*args.output).parse().unwrap();
    let data: Vec<u8> = fs::read(input).expect("Failed to read input file!");

    if let Some(output_checksum) = (args.clone()).output_checksum {
        let checksum = sha_checksum(&data);
        let checksum_b64 = base64::encode(checksum.as_slice());
        fs::write(output_checksum, checksum_b64.as_bytes())
            .expect("Failed to write checksum file!");
    }
    let pass = read_password_from_tty(Some("Password: ")).unwrap();
    let key = create_key(&pass);
    let enc_data = encrypt_data(data.as_slice(), key.as_slice());
    fs::write(output, enc_data.as_slice()).expect("Failed to write output file!");
}

/// Decrypts a des encrypted file.
/// Brute forces if the dictionary argument was passed
fn decrypt(_opts: &Opts, args: &Decrypt) {
    let mut tt = TimeTaker::new();
    tt.take("start");
    let input: String = (*args.input).parse().unwrap();
    let output: String = (*args.output).parse().unwrap();
    let dictionary = args.dictionary.clone();
    let data = fs::read(input).expect("Failed to read input file!");

    if let Some(input_checksum) = (args.clone()).input_checksum {
        let bin_content = fs::read(input_checksum).expect("Failed to read checksum file!");
        let data_checksum = base64::decode(bin_content.as_slice()).unwrap();

        if let Some(dict) = dictionary {
            tt.take("decryption-start");
            if let Some(dec_data) = decrypt_with_dictionary_file(dict, &data, &data_checksum) {
                fs::write(output, &dec_data).expect("Failed to write output file!");
                println!(
                    "Decryption took {:.2}s",
                    tt.since("decryption-start").unwrap().as_secs_f32()
                );
                println!("Finished {:.2}s!", tt.since("start").unwrap().as_secs_f32());
            } else {
                println!("\nNo password found!");
                println!("Finished {:.2}s!", tt.since("start").unwrap().as_secs_f32());
            }
        } else {
            let sp = spinner("Brute force decrypting file");
            if let Some(dec_data) = decrypt_brute_brute_force(&data, &data_checksum) {
                sp.stop();
                fs::write(output, &dec_data).expect("Failed to write output file!");
                println!("Finished {:.2}s!", tt.since("start").unwrap().as_secs_f32());
            } else {
                sp.stop();
                println!("\nNo fitting key found. (This should have been impossible)")
            }
        }
    } else {
        let pass = read_password_from_tty(Some("Password: ")).unwrap();
        let key = create_key(&pass);
        let result = decrypt_data(&data, key.as_slice());
        fs::write(output, &result).expect("Failed to write output file!");
    }
}

const SHA256: &str = "sha256";

/// Creates a dictionary from an input file and writes it to the output file
fn create_dictionary(_opts: &Opts, args: &CreateDictionary) {
    let mut tt = TimeTaker::new();
    tt.take("start");
    let sp = spinner("Reading input file...");
    let input: String = (*args.input).parse().unwrap();
    // TODO: Some form of removing duplicates (without itertools)
    let fout = File::create(args.output.clone()).unwrap();
    let writer = BufWriter::new(fout);
    let handle;

    let content = fs::read_to_string(input).expect("Failed to read content");
    let lines = content.par_lines();
    let entry_count = lines.clone().count() as u64;
    sp.stop();

    let mut pb = ProgressBar::new(entry_count);
    pb.set_max_refresh_rate(Some(Duration::from_millis(200)));
    let (rx, tx) = sync_channel::<DataEntry>(100_00_000);

    let mut bdf_file = BDFWriter::new(writer, entry_count, args.compress != 0);
    bdf_file.set_compression_level(args.compress);
    bdf_file
        .set_entries_per_chunk(args.entries_per_chunk)
        .expect("Failed to set the entries per chunk.");
    bdf_file
        .add_lookup_entry(HashEntry::new(SHA256.to_string(), 32))
        .expect("Failed to add sha256 lookup entry");

    handle = thread::spawn(move || {
        for entry in tx {
            if let Err(e) = bdf_file.add_data_entry(entry) {
                println!("{:?}", e);
            }
            pb.inc();
        }
        pb.finish();
        bdf_file
            .finish()
            .expect("failed to finish the writing process");
    });

    tt.take("creation");
    let re = Regex::new("[\\x00\\x08\\x0B\\x0C\\x0E-\\x1F\\t\\r\\a\\n]").unwrap();
    lines
        .map(|line| -> String { re.replace_all(line, "").to_string() })
        .map(|pw| -> DataEntry {
            let key256 = sha256(&pw);
            let mut data_entry = DataEntry::new(pw);
            data_entry.add_hash_value(SHA256.to_string(), key256);

            data_entry
        })
        .for_each_with(rx, |rx, data_entry| {
            rx.send(data_entry)
                .expect("Failed to send value to channel.");
        });

    if let Err(_err) = handle.join() {
        println!("Failed to join!");
    }
    println!(
        "Rainbow table creation took {:.2}s",
        tt.since("creation").unwrap().as_secs_f32()
    );
    println!("Finished {:.2}s!", tt.since("start").unwrap().as_secs_f32());
}

/// Creates a new spinner with a given text
fn spinner(text: &str) -> Spinner {
    Spinner::new(Spinners::Dots2, text.into())
}

/// Decrypts the file using a bdf dictionary
/// The files content is read chunk by chunk to reduce the memory impact since dictionary
/// files tend to be several gigabytes in size
fn decrypt_with_dictionary_file(
    filename: String,
    data: &Vec<u8>,
    data_checksum: &Vec<u8>,
) -> Option<Vec<u8>> {
    let sp = spinner("Reading dictionary...");
    let f = File::open(&filename).expect("Failed to open dictionary file.");
    let reader = BufReader::new(f);
    let mut bdf_file = BDFReader::new(reader);
    bdf_file
        .read_metadata()
        .expect("failed to read the metadata of the file");
    let mut chunk_count = 0;
    if let Some(meta) = &bdf_file.metadata {
        chunk_count = meta.chunk_count;
    }
    let mut pb = ProgressBar::new(chunk_count as u64);
    let (rx, tx) = sync_channel::<Vec<DataEntry>>(100);
    let _handle = thread::spawn(move || {
        let mut lookup_table = HashLookupTable::new(HashMap::new());
        if let Ok(table) = bdf_file.read_lookup_table() {
            lookup_table = table.clone();
        }
        while let Ok(next_chunk) = &mut bdf_file.next_chunk() {
            if let Ok(entries) = next_chunk.data_entries(&lookup_table) {
                if let Err(_) = rx.send(entries) {}
            }
        }
    });
    sp.stop();
    let mut result_data: Option<Vec<u8>> = None;
    for entries in tx {
        let pw_table: Vec<(&String, Vec<u8>)> = entries
            .par_iter()
            .map(|entry: &DataEntry| {
                let pw = &entry.plain;
                let key: &Vec<u8> = entry.get_hash_value(SHA256.to_string()).unwrap();

                (pw, key[0..8].to_vec())
            })
            .collect();
        pb.inc();
        if let Some(dec_data) = decrypt_with_dictionary(&data, pw_table, &data_checksum) {
            result_data = Some(dec_data);
            break;
        }
    }
    pb.finish();
    result_data
}
