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
const BATCH_SIZE: usize = 64;

#[cfg(feature = "test-utilities")]
fn main() {
    use prism::transaction::tests::generate_random_transaction;

    let tx = generate_random_transaction();
    let raw_inputs = serialize(&tx.input).unwrap();
    let raw_outputs = serialize(&tx.output).unwrap();
    let raw: &[u8] = &[&raw_inputs[..], &raw_outputs[..]].concat(); // we can also use Vec extend, don't know which is better

    let mut csprng: ThreadRng = thread_rng();
    let keypairs: Vec<Keypair> = (0..64).map(|_| Keypair::generate(&mut csprng)).collect();
    let messages: Vec<&[u8]> = (0..BATCH_SIZE).map(|_| raw).collect();
    let signatures:  Vec<Signature> = keypairs.iter().map(|key| key.sign(&raw)).collect();
    let public_keys: Vec<PublicKey> = keypairs.iter().map(|key| key.public).collect();

    let start = Instant::now();
    for _ in 0..REPEAT {
        verify_batch(&messages[..], &signatures[..], &public_keys[..]);
    }
    let end = Instant::now();
    let time = end.duration_since(start).as_micros() as f64;
    println!("Tx verifying {} mu s", time/((REPEAT*BATCH_SIZE) as f64));

}