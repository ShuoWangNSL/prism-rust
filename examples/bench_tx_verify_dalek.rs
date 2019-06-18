use std::time::Instant;
use bincode::serialize;
extern crate ed25519_dalek;
extern crate rand;

use rand::thread_rng;
use rand::rngs::ThreadRng;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;
use ed25519_dalek::PublicKey;
use ed25519_dalek::verify_batch;

const REPEAT: usize = 2000;

#[cfg(feature = "test-utilities")]
fn main() {
    use prism::transaction::tests::generate_random_transaction;

    let tx = generate_random_transaction();
    let raw_inputs = serialize(&tx.input).unwrap();
    let raw_outputs = serialize(&tx.output).unwrap();
    let raw = [&raw_inputs[..], &raw_outputs[..]].concat(); // we can also use Vec extend, don't know which is better

    let mut csprng: ThreadRng = thread_rng();
    let keypair: Keypair = Keypair::generate(&mut csprng);

    // signing
    let start = Instant::now();
    for _ in 0..REPEAT {
        keypair.sign(&raw);
    }
    let end = Instant::now();
    let time = end.duration_since(start).as_micros() as f64;
    println!("Tx signing {} mu s", time/(REPEAT as f64));
    

    // verification
    let signature: Signature = keypair.sign(&raw);
    let public_key: PublicKey = keypair.public;

    let start = Instant::now();
    for _ in 0..REPEAT {
        public_key.verify(&raw, &signature);
    }
    let end = Instant::now();
    let time = end.duration_since(start).as_micros() as f64;
    println!("Tx verifying {} mu s", time/((REPEAT) as f64));

}