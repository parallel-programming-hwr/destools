pub mod lib;

use crate::lib::crypt::{decrypt_with_dictionary, encrypt_data};
use crate::lib::hash::{create_hmac, sha256};
use crate::lib::timing::TimeTaker;
use bdf::chunks::{DataEntry, HashEntry, HashLookupTable};
use bdf::io::{BDFReader, BDFWriter};
use crossbeam_channel::bounded;
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
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
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
}

#[derive(StructOpt, Clone)]
struct Decrypt {
    /// The input file
    #[structopt(short = "i", long = "input", default_value = "input.des")]
    input: String,

    /// The output file
    #[structopt(short = "o", long = "output", default_value = "output.txt")]
    output: String,

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

    let pass = read_password_from_tty(Some("Password: ")).unwrap();
    let sha256_key = sha256(&pass);
    let key = &sha256_key[0..8];
    let mut data_hmac = create_hmac(&sha256_key, &data).expect("failed to create hmac");
    let mut enc_data = encrypt_data(data.as_slice(), &key);
    enc_data.append(&mut data_hmac);
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

    if let Some(dict) = dictionary {
        tt.take("decryption-start");
        if let Some(dec_data) = decrypt_with_dictionary_file(dict, &data) {
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
        println!("No checksum file given!");
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

    let content = fs::read_to_string(input).expect("Failed to read content");
    let lines = content.par_lines();
    let entry_count = lines.clone().count() as u64;
    sp.stop();

    let mut pb = ProgressBar::new(entry_count);
    pb.set_max_refresh_rate(Some(Duration::from_millis(200)));

    let mut bdf_file = BDFWriter::new(fout, entry_count, args.compress != 0);
    bdf_file.set_compression_level(args.compress);
    bdf_file
        .set_entries_per_chunk(args.entries_per_chunk)
        .expect("Failed to set the entries per chunk.");
    bdf_file
        .add_lookup_entry(HashEntry::new(SHA256.to_string(), 32))
        .expect("Failed to add sha256 lookup entry");

    let mut threads = Vec::new();
    let (rx, tx) = bounded::<DataEntry>(100_00_000);
    let bdf_arc = Arc::new(Mutex::new(bdf_file));
    let pb_arc = Arc::new(Mutex::new(pb));

    for _ in 0..(num_cpus::get() as f32 / 4f32).ceil() as usize {
        let tx = tx.clone();
        let bdf_arc = Arc::clone(&bdf_arc);
        let pb_arc = Arc::clone(&pb_arc);
        threads.push(thread::spawn(move || {
            for entry in tx {
                if let Err(e) = &bdf_arc.lock().unwrap().add_data_entry(entry) {
                    println!("{:?}", e);
                }
                pb_arc.lock().unwrap().inc();
            }
        }));
    }

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

    for handle in threads {
        if let Err(_err) = handle.join() {
            println!("Failed to join!");
        }
    }
    bdf_arc
        .lock()
        .unwrap()
        .finish()
        .expect("failed to finish the writing process");
    pb_arc.lock().unwrap().finish();
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
fn decrypt_with_dictionary_file(filename: String, data: &Vec<u8>) -> Option<Vec<u8>> {
    let sp = spinner("Reading dictionary...");
    let f = File::open(&filename).expect("Failed to open dictionary file.");
    let mut bdf_file = BDFReader::new(f);
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
        let pw_table: Vec<(&String, &Vec<u8>)> = entries
            .par_iter()
            .map(|entry: &DataEntry| {
                let pw = &entry.plain;
                let key: &Vec<u8> = entry.get_hash_value(SHA256.to_string()).unwrap();

                (pw, key)
            })
            .collect();
        pb.inc();
        if let Some(dec_data) = decrypt_with_dictionary(&data, pw_table) {
            result_data = Some(dec_data);
            break;
        }
    }
    pb.finish();
    result_data
}
