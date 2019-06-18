use prism::block::Block;
//use prism::blockchain::utils as bc_utils;
use prism::transaction::{Input, Output, CoinId, Transaction};
use prism::crypto::sign::{KeyPair, PubKey, Signable, Signature};
use prism::utxodb::UtxoDatabase;
use prism::crypto::hash::Hashable;
use prism::experiment::ico;
use prism::wallet::Wallet;
use std::sync::mpsc;
use std::time::Instant;
use std::thread;
use std::sync::Arc;
use log::{debug, error, info};
use std::process;
use bincode::serialize;
const REPEAT: usize = 20000;

#[cfg(feature = "test-utilities")]
fn main() {
    use prism::transaction::tests::generate_random_input;
    use prism::transaction::tests::generate_random_output;
    use prism::transaction::tests::generate_random_transaction;


    let keypair = KeyPair::random();

    let tx = generate_random_transaction();
    let raw_inputs = serialize(&tx.input).unwrap();
    let raw_outputs = serialize(&tx.output).unwrap();
    let raw = [&raw_inputs[..], &raw_outputs[..]].concat(); // we can also use Vec extend, don't know which is better
    let start = Instant::now();
    for _ in 0..REPEAT {
        keypair.sign(&raw);
    }
    let end = Instant::now();
    let time = end.duration_since(start).as_micros() as f64;
    println!("Tx signing {} mu s", time/(REPEAT as f64));

    let signature: Signature = keypair.sign(&raw);
    let public_key = keypair.public_key();

    let start = Instant::now();
    for _ in 0..REPEAT {
        public_key.verify(&raw, &signature);
    }
    let end = Instant::now();
    let time = end.duration_since(start).as_micros() as f64;
    println!("Tx verifying {} mu s", time/(REPEAT as f64));

}