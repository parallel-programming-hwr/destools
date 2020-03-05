pub mod lib;

use crate::lib::crypt::{
    decrypt_brute_brute_force, decrypt_data, decrypt_with_dictionary, encrypt_data,
};
use crate::lib::hash::{create_key, map_to_keys, sha_checksum, PassKey};
use pbr::ProgressBar;
use rayon::prelude::*;
use rpassword;
use rpassword::read_password_from_tty;
use spinners::{Spinner, Spinners};
use std::fs;
use std::fs::File;
use std::io::Write;
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
    let key = create_key(pass);
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
            let sp = spinner("Reading dictionary...");
            let dictionary = fs::read_to_string(dict).expect("Failed to read dictionary file!");
            let lines = dictionary.lines().collect::<Vec<&str>>();

            let pw_table: Vec<PassKey> = lines
                .par_iter()
                .map(|line| {
                    let parts: Vec<&str> = line.split(",").collect::<Vec<&str>>();
                    let pw = parts[0].parse().unwrap();
                    let key_str: String = parts[1].parse().unwrap();
                    let key = base64::decode(&key_str).unwrap();

                    (pw, key)
                })
                .collect();
            sp.message("Dictionary decrypting file multithreaded".into());
            if let Some(dec_data) = decrypt_with_dictionary(&data, pw_table, &data_checksum) {
                sp.stop();
                fs::write(output, &dec_data).expect("Failed to write output file!");
                println!("\nFinished!");
            } else {
                sp.stop();
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
        let key = create_key(pass);
        let result = decrypt_data(&data, key.as_slice());
        fs::write(output, &result).expect("Failed to write output file!");
    }
}

/// Creates a dictionary from an input file and writes it to the output file
fn create_dictionary(_opts: &Opts, args: &CreateDictionary) {
    let input: String = (*args.input).parse().unwrap();
    let sp = spinner("Parsing passwords...");
    let dictionary: Vec<PassKey>;
    {
        let passwords = get_lines(&input);
        // TODO: Some form of removing duplicates (without itertools)
        sp.message("Mapping passwords to keys".into());
        dictionary = map_to_keys(passwords);
    }
    sp.message("Encoding data to lines".into());
    let dict_lines: Vec<String> = dictionary
        .par_iter()
        .map(|(pw, key): &PassKey| -> String {
            let key_base64 = base64::encode(key.as_slice());
            format!("{},{}\n", pw, key_base64)
        })
        .collect();
    sp.stop();
    println!("\rWriting passwords to file...");
    let mut fout = File::create(args.output.clone()).unwrap();
    let mut pb = ProgressBar::new(dict_lines.len() as u64);
    pb.set_max_refresh_rate(Some(Duration::from_millis(200)));
    for line in dict_lines {
        fout.write(&line.into_bytes()).unwrap();
        pb.inc();
    }
    pb.finish();
    println!("Finished!");
}

fn get_lines(filename: &str) -> Vec<String> {
    let contents = fs::read_to_string(filename).expect("Failed to read input file!");
    let lines = contents.lines().collect::<Vec<&str>>();
    lines
        .par_iter()
        .map(|s| -> String { s.parse().unwrap() })
        .collect()
}

/// Creates a new spinner with a given text
fn spinner(text: &str) -> Spinner {
    Spinner::new(Spinners::Dots2, text.into())
}
