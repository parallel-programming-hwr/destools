use std::thread;
use may::sync::mpmc::{Sender, Receiver, channel};
use crate::lib::crypt::{decrypt_data};
use crate::lib::hash::{sha_checksum, PassKey};
use std::thread::JoinHandle;

type ChannelControls<T> = (Sender<ThreadControlMessage<T>>, Receiver<ThreadControlMessage<T>>);
type DecryptData = (Option<Vec<u8>>, Option<PassKey>);

#[derive(Debug)]
pub struct ThreadControlMessage<T> {
    message_type: MessageType,
    data: Option<T>,
}

#[derive(Debug)]
pub enum MessageType {
    Data,
    Stop,
    DataRequest,
}

impl<T> ThreadControlMessage<T> {
    /// Creates a new data message
    fn new_data(data: T) -> Self {
        return Self {
            message_type: MessageType::Data,
            data: Some(data),
        };
    }
    /// Creates a new stop message
    fn new_stop() -> Self {
        return Self {
            message_type: MessageType::Stop,
            data: None,
        }
    }
    /// Creates a new message for data requests
    fn new_request() -> Self {
        return Self {
            message_type: MessageType::DataRequest,
            data: None,
        }
    }
}

/// Creates a channel of a specific type
pub fn create_channel<T>() -> ChannelControls<T> {
    let chan = channel::<ThreadControlMessage<T>>();
    chan
}

/// Returns the number of cpus there are
pub fn cpu_count() -> u8 {
    return num_cpus::get() as u8;
}

/// Decrypts data multithreaded
pub fn decrypt_data_threaded(data: Vec<u8>, pw_table: &Vec<PassKey>, data_checksum: Vec<u8>) -> Option<Vec<u8>> {
    let chan = create_channel::<DecryptData>();
    let (rx, tx1) = chan;
    let chan2 = create_channel::<DecryptData>();
    let (rx2, tx) = chan2;
    let mut entry_index = 0;
    let mut threads: Vec<JoinHandle<()>> = vec![];
    let num_threads = cpu_count();
    println!("Creating {} threads...", num_threads);
    for i in 0u8..num_threads {
        print!("Starting Thread {}\r", i);
        let rx1 = rx2.clone();
        let tx1 = tx1.clone();
        let data_checksum = data_checksum.clone();
        let data = data.clone();
        let child = thread::spawn(move || {
            decrypt_data_coro(&(rx1, tx1), data, data_checksum);
        });
        threads.push(child);
        if let Ok(entry) = next_password(pw_table, entry_index) {
            rx.send(ThreadControlMessage::new_data((None, Some(entry)))).unwrap();
            entry_index += 1;
        }
    }
    println!("Starting main loop...");
    loop {
        if entry_index % 100 == 0 {
            print!("{} out of {} Passwords tested\r", entry_index, pw_table.len());
        }
        let message = tx.recv().unwrap();
        if let Ok(next_entry) = next_password(pw_table, entry_index) {
            let msg_data: DecryptData = (None, Some(next_entry));
            match message.message_type {
                MessageType::DataRequest => {
                    rx.send(ThreadControlMessage::<DecryptData>::new_data(msg_data)).unwrap();
                },
                MessageType::Data => {
                    if let Some((result_data, pass_key)) = message.data {
                        if let Some(decrypted_data) = result_data {
                            rx.send(ThreadControlMessage::new_stop()).unwrap();
                            println!();
                            println!("Received data.");
                            if let Some((pw, _key)) = pass_key {
                                println!("Password is: {}", pw);
                            }
                            return Some(decrypted_data);
                        } else {
                            rx.send(ThreadControlMessage::<DecryptData>::new_data(msg_data)).unwrap();
                        }
                    } else {
                        rx.send(ThreadControlMessage::<DecryptData>::new_data(msg_data)).unwrap();
                    }
                }
                _ => {}
            }
            entry_index += 1;
        } else {
            rx.send(ThreadControlMessage::new_stop()).unwrap();
            println!();
            println!("No remaining passwords!");
            return None;
        }
    }
}

/// Returns the next password or none if none are left
fn next_password(pw_table: &Vec<PassKey>, index: usize) -> Result<PassKey, &str> {
    if index < pw_table.len() {
        Ok(pw_table[index].clone())
    } else {
        Err("No remaining passwords")
    }
}

/// Coroutine to decrypt data
fn decrypt_data_coro(controls: &ChannelControls<DecryptData>, data: Vec<u8>, check: Vec<u8>) {
    loop {
        let (tx, rx) = controls;
        if let Ok(message) = rx.recv() {
            match message.message_type {
                MessageType::Data => {
                    if let Some((_, pass_key)) = message.data {
                        if let Some((_pw, key)) = pass_key.clone() {
                            let decrypted_data = decrypt_data(&data, key.as_slice());
                            let decr_check = sha_checksum(&decrypted_data);
                            if decr_check == check {
                                tx.send(ThreadControlMessage::new_data((Some(decrypted_data), pass_key))).unwrap();
                            } else {
                                if let Err(_e) = tx.send(ThreadControlMessage::new_request()) {
                                    break;
                                }
                            }
                        }
                    }
                },
                MessageType::Stop => {
                    break;
                },
                _ => {
                    tx.send(ThreadControlMessage::new_request()).unwrap();
                }
            }
        } else {
            break;
        }
    }
}