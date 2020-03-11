pub mod lib;

use crate::lib::crypt::{
    decrypt_brute_brute_force, decrypt_data, decrypt_with_dictionary, encrypt_data,
};
use crate::lib::hash::{create_key, sha_checksum, PassKey};
use pbr::ProgressBar;
use rayon::prelude::*;
use rayon::str;
use regex::Regex;
use rpassword;
use rpassword::read_password_from_tty;
use spinners::{Spinner, Spinners};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
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
    #[structopt(short = "o", long = "output", default_value = "dictionary.tsv")]
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
    let input: String = (*args.input).parse().unwrap();
    let output: String = (*args.output).parse().unwrap();
    let dictionary = args.dictionary.clone();
    let data = fs::read(input).expect("Failed to read input file!");

    if let Some(input_checksum) = (args.clone()).input_checksum {
        let bin_content = fs::read(input_checksum).expect("Failed to read checksum file!");
        let data_checksum = base64::decode(bin_content.as_slice()).unwrap();

        if let Some(dict) = dictionary {
            if let Some(dec_data) = decrypt_with_dictionary_file(dict, &data, &data_checksum) {
                fs::write(output, &dec_data).expect("Failed to write output file!");
                println!("\nFinished!");
            } else {
                println!("\nNo password found!");
            }
        } else {
            let sp = spinner("Brute force decrypting file");
            if let Some(dec_data) = decrypt_brute_brute_force(&data, &data_checksum) {
                sp.stop();
                fs::write(output, &dec_data).expect("Failed to write output file!");
                println!("\nFinished!");
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

/// Creates a dictionary from an input file and writes it to the output file
fn create_dictionary(_opts: &Opts, args: &CreateDictionary) {
    let input: String = (*args.input).parse().unwrap();
    // TODO: Some form of removing duplicates (without itertools)
    let fout = File::create(args.output.clone()).unwrap();
    let mut writer = BufWriter::new(fout);
    let handle;
    {
        let content = fs::read_to_string(input).expect("Failed to read content");
        let lines = content.par_lines();
        let mut pb;
        {
            pb = ProgressBar::new(lines.clone().count() as u64);
        }
        pb.set_max_refresh_rate(Some(Duration::from_millis(200)));
        let (rx, tx) = sync_channel::<String>(100_000_000);
        handle = thread::spawn(move || {
            for line in tx {
                writer.write(&line.as_bytes()).unwrap();
                pb.inc();
            }
            pb.finish();
            writer.flush().expect("Failed to flush the file writer.");
        });
        let re = Regex::new("[\\x00\\x08\\x0B\\x0C\\x0E-\\x1F\\t\\r\\a\\n]").unwrap();
        lines
            .map(|line| -> String { re.replace_all(line, "").to_string() })
            .map(|pw| -> String {
                let key = create_key(pw.replace("\t", "").as_ref());
                let key_base64 = base64::encode(key.as_slice());
                format!("{}\t{}\n", pw, key_base64)
            })
            .for_each_with(rx, |rx, line| {
                rx.send(line).expect("Failed to send value to channel.");
            });
    }
    if let Err(_err) = handle.join() {
        println!("Failed to join!");
    }
    println!("Finished!");
}

/// Creates a new spinner with a given text
fn spinner(text: &str) -> Spinner {
    Spinner::new(Spinners::Dots2, text.into())
}

const LINES_PER_CHUNK: usize = 10000000;

fn decrypt_with_dictionary_file(
    filename: String,
    data: &Vec<u8>,
    data_checksum: &Vec<u8>,
) -> Option<Vec<u8>> {
    let sp = spinner("Reading dictionary...");
    let f = File::open(&filename).expect("Failed to open dictionary file.");
    let reader = BufReader::new(f);
    let mut pb =
        ProgressBar::new((get_line_count(&filename) as f64 / LINES_PER_CHUNK as f64).ceil() as u64);
    let (rx, tx) = sync_channel::<Vec<String>>(10);
    let _handle = thread::spawn(move || {
        let mut line_vec: Vec<String> = vec![];
        reader.lines().for_each(|line_result| {
            if line_vec.len() > LINES_PER_CHUNK {
                if let Err(_) = rx.send(line_vec.clone()) {}
                line_vec.clear();
            }
            match line_result {
                Ok(line) => line_vec.push(line),
                Err(err) => eprintln!("Failed with err {}", err),
            }
        });
        if let Err(_) = rx.send(line_vec.clone()) {}
        line_vec.clear();
    });
    sp.stop();
    let mut result_data: Option<Vec<u8>> = None;
    for lines in tx {
        let pw_table: Vec<PassKey> = lines
            .par_iter()
            .map(|line| {
                let parts: Vec<&str> = line.split("\t").collect::<Vec<&str>>();
                let pw = parts[0].parse().unwrap();
                let key_str: String = parts[1].parse().unwrap();
                let key = base64::decode(&key_str).unwrap();

                (pw, key)
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

fn get_line_count(fname: &str) -> usize {
    let f = File::open(fname).expect("Failed to open file to get the line count.");
    let reader = BufReader::new(f);
    return reader.lines().count();
}
