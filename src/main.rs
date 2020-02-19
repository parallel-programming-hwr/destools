pub mod lib;
use structopt::StructOpt;
use std::fs::File;
use std::io::{Read, Write};
use crate::lib::crypt::{encrypt_data, decrypt_data, decrypt_with_dictionary, decrypt_brute_brute_force};
use rpassword;
use rpassword::{read_password_from_tty};
use crate::lib::hash::{create_key, map_to_keys, sha_checksum, PassKey};
use rayon::prelude::*;
use itertools::Itertools;

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
    CreateDictionary(CreateDictionary)
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
    dictionary: Option<String>
}

#[derive(StructOpt, Clone)]
struct CreateDictionary {
    /// The input dictionary file.
    #[structopt(short = "i", long = "input", default_value = "dictionary.txt")]
    input: String,

    /// The output dictionary file
    #[structopt(short = "o", long = "output", default_value = "dictionary.csv")]
    output: String,
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
    let input = (*args.input).parse().unwrap();
    let output = (*args.output).parse().unwrap();
    let data: Vec<u8> = read_file_binary(input);

    if let Some(output_checksum) = (args.clone()).output_checksum {
        let checksum = sha_checksum(&data);
        let checksum_b64 = base64::encode(checksum.as_slice());
        write_file(output_checksum, checksum_b64.as_bytes());
    }
    let pass = read_password_from_tty(Some("Password: ")).unwrap();
    let key = create_key(pass);
    let enc_data = encrypt_data(data.as_slice(), key.as_slice());
    write_file(output, enc_data.as_slice());
}

/// Decrypts a des encrypted file.
/// Brute forces if the dictionary argument was passed
fn decrypt(_opts: &Opts, args: &Decrypt) {
    let input = (*args.input).parse().unwrap();
    let output = (*args.output).parse().unwrap();
    let dictionary = args.dictionary.clone();
    let data = read_file_binary(input);

    if let Some(input_checksum) = (args.clone()).input_checksum {
        let bin_content = read_file_binary(input_checksum);
        let data_checksum = base64::decode(bin_content.as_slice()).unwrap();

        if let Some(dict) = dictionary {
            println!("Reading dictionary...");
            let dictionary = read_file(dict);
            let lines = dictionary.lines().collect::<Vec<&str>>();

            let pw_table: Vec<PassKey> = lines.par_iter().map(|line| {
                let parts: Vec<&str> = line.split(",").collect::<Vec<&str>>();
                let pw = parts[0].parse().unwrap();
                let key_str: String = parts[1].parse().unwrap();
                let key = base64::decode(&key_str).unwrap();
                (pw, key)
            }).collect();

            println!("Starting multithreaded decryption...");
            if let Some(dec_data) = decrypt_with_dictionary(&data, pw_table, &data_checksum) {
                write_file(output, &dec_data);
                println!("Finished!");
            } else {
                println!("No password found!");
            }
        } else {
            println!("Starting brute force multithreaded decryption...");
            if let Some(dec_data) = decrypt_brute_brute_force(&data, &data_checksum) {
                write_file(output, &dec_data);
                println!("Finished!");
            } else {
                println!("No fitting key found. (This should have been impossible)")
            }
        }
    } else {
        let pass = read_password_from_tty(Some("Password: ")).unwrap();
        let key = create_key(pass);
        let result = decrypt_data(&data, key.as_slice());
        write_file(output, &result);
    }
}

/// Creates a dictionary from an input file and writes it to the output file
fn create_dictionary(_opts: &Opts, args: &CreateDictionary) {
    let input  = (*args.input).parse().unwrap();
    let contents = read_file(input);
    let lines = contents.lines().collect::<Vec<&str>>();
    println!("Parsing {} passwords...", lines.len());

    let pws: Vec<String> = lines.par_iter().map(| s | -> String {
        s.parse().unwrap()
    }).collect();
    println!("Removing duplicates...");
    let passwords = pws.iter().unique().collect_vec();
    println!("Mapping passwords to keys...");
    let dictionary = map_to_keys(passwords);
    println!("Writing passwords to file...");
    let mut fout = File::create(args.output.clone()).unwrap();

    for entry in dictionary.iter() {
        let key = base64::encode((*entry).1.as_slice());
        let line = format!("{},{}\n", (*entry).0, key);
        fout.write(&line.into_bytes()).unwrap();
    }
    println!("Finished!");
}

/// Reads a file to the end and returns the content as byte array
fn read_file_binary(filename: String) -> Vec<u8> {
    let mut fin = File::open(filename).unwrap();
    let mut data: Vec<u8> = vec![];
    fin.read_to_end(&mut data).unwrap();
    return data;
}

/// Reads a file to the end and returns the contents as a string
fn read_file(filename: String) -> String {
    let mut fin = File::open(filename).unwrap();
    let mut contents= String::new();
    fin.read_to_string(&mut contents).unwrap();
    return contents;
}

/// writes binary data to a file
fn write_file(filename: String, data: &[u8]) {
    let mut fout = File::create(filename).unwrap();
    fout.write(data).unwrap();
}