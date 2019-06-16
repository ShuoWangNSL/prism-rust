use std::cell::RefCell;
use crate::crypto::hash::Hashable;
use crate::crypto::sign::{KeyPair, PubKey, Signable};
use crate::transaction::{Address, Authorization, CoinId, Input, Output, Transaction};
use bincode::{deserialize, serialize};
use std::{error, fmt};
use std::convert::TryInto;
use std::sync::{mpsc, Arc, Mutex};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
extern crate lmdb_zero as lmdb;
extern crate tempdir;


pub const COIN_CF: &str = "COIN";
pub const KEYPAIR_CF: &str = "KEYPAIR";     // &Address to &KeyPairPKCS8

pub type Result<T> = std::result::Result<T, WalletError>;

/// A data structure to maintain key pairs and their coins, and to generate transactions.
pub struct Wallet<'a> {
    /// The underlying environment.
    env: Arc<lmdb::Environment>,
    /// The underlying LMDB handle.
    db: lmdb::Database<'a>,
    /// Keep key pair (in pkcs8 bytes) in memory for performance, it's duplicated in database as well.
    key_pair: Mutex<HashMap<Address, Vec<u8>>>,
    counter: AtomicUsize,
}


impl<'a> Wallet<'a> {
    fn open(path: &str) -> Result<Self> {
        let env = unsafe {
            let mut builder = lmdb::EnvBuilder::new().unwrap();
            builder.set_maxdbs(2).unwrap();
            builder.open(tempdir::TempDir::new_in("/tmp/", path).unwrap().path().to_str().unwrap(),
                         lmdb::open::Flags::empty(), 0o600).unwrap()
        };
        let env = Arc::new(env);
        let env_clone = Arc::clone(&env);
        let db: lmdb::Database = lmdb::Database::open(
            env, None, &lmdb::DatabaseOptions::defaults())
            .unwrap();
        return Ok(Self { env: env_clone, db: db, key_pair: Mutex::new(HashMap::new()), counter: AtomicUsize::new(0), });
    }

    pub fn new(path: &str) -> Result<Self> {
        // TODO: Remove old data
//        rocksdb::DB::destroy(&rocksdb::Options::default(), &path)?;
        return Self::open(path);
    }

    pub fn number_of_coins(&self) -> usize {
        self.counter.load(Ordering::Relaxed)
    }

    /// Generate a new key pair
    pub fn generate_keypair(&self) -> Result<Address> {
        let keypair = KeyPair::random();
        let k: Address = keypair.public_key().hash();
        let v = keypair.pkcs8_bytes;
        let mut key_pair = self.key_pair.lock().unwrap();
        key_pair.insert(k,v);
        Ok(k)
    }


    pub fn load_keypair(&self, keypair: KeyPair) -> Result<Address> {
//        let cf = self.db.cf_handle(KEYPAIR_CF).unwrap();
//        self.db.put_cf(cf, &addr, &keypair.pkcs8_bytes)?;
        let addr: Address = keypair.public_key().hash();
        let mut key_pair = self.key_pair.lock().unwrap();
        key_pair.insert(addr,keypair.pkcs8_bytes);
        Ok(addr)
    }

    /// Get the list of addresses for which we have a key pair
    pub fn addresses(&self) -> Result<Vec<Address>> {
        let key_pair = self.key_pair.lock().unwrap();
        let addrs = key_pair.keys().cloned().collect();
        Ok(addrs)
    }

    fn keypair(&self, addr: &Address) -> Result<KeyPair> {
        let key_pair = self.key_pair.lock().unwrap();
        if let Some(v) = key_pair.get(addr) {
            return Ok(KeyPair::from_pkcs8(v.clone()));
        }
        Err(WalletError::MissingKeyPair)
    }

    fn contains_keypair(&self, addr: &Address) -> bool {
        let key_pair = self.key_pair.lock().unwrap();
        if key_pair.contains_key(addr) {
            return true;
        }
        false
    }

    pub fn apply_diff(&mut self, add: &[Input], remove: &[Input]) -> Result<()> {
        // batch write/delete
        let txn = lmdb::WriteTransaction::new(Arc::clone(&self.env))?;
        {
            let mut access = txn.access();
            for coin in add {
                // TODO: It's so funny that we have to do this for every added coin.
                // TODO: We could reuse objects from utxo db.
                if self.contains_keypair(&coin.owner) {
                    let output = Output {
                        value: coin.value,
                        recipient: coin.owner,
                    };
                    let key = serialize(&coin.coin).unwrap();
                    let val = serialize(&output).unwrap();
                    access.put(&self.db, &key, &val, lmdb::put::Flags::empty())?;
                    self.counter.fetch_add(1, Ordering::Relaxed);
                }
            }

            for coin in remove {
                let key = serialize(&coin.coin).unwrap();
                access.del_key(&self.db, &key)?;
            }
        }
        // commit the batch
        txn.commit().unwrap();
        Ok(())
    }

    /// Returns the sum of values of all the coin in the wallet
    pub fn balance(&self) -> Result<u64> {
        let txn = lmdb::WriteTransaction::new(Arc::clone(&self.env))?;
        let mut balance: u64 = 0;
        {
            let mut access = txn.access();
            let mut cursor = txn.cursor(&self.db).unwrap();
            let mut iter = lmdb::CursorIter::new(
                lmdb::MaybeOwned::Borrowed(&mut cursor), &*access,
                |c, a| c.first(a), lmdb::Cursor::next::<Vec<u8>, Vec<u8>>).unwrap();
            balance = iter
                .map(|data|   {
                    let (_ ,v) = data.unwrap();
                    let coin_data: Output = bincode::deserialize(v.as_ref()).unwrap();
                    coin_data.value
                })
                .sum::<u64>();
        }
        Ok(balance)
    }
//
//    /// Create a transaction using the wallet coins
//    pub fn create_transaction(&self, recipient: Address, value: u64, previous_used_coin: Option<Input> ) -> Result<Transaction> {
//        let mut coins_to_use: Vec<Input> = vec![];
//        let mut value_sum = 0u64;
//        let cf = self.db.cf_handle(COIN_CF).unwrap();
//        let iter = match previous_used_coin {
//            Some(c) => {
//                let prev_key = serialize(&c.coin).unwrap();
//                self.db.iterator_cf(cf, rocksdb::IteratorMode::From(&prev_key, rocksdb::Direction::Forward))?
//            },
//            None => self.db.iterator_cf(cf, rocksdb::IteratorMode::Start)?
//        };
//        // iterate through our wallet
//        for (k, v) in iter {
//            let coin_id: CoinId = bincode::deserialize(k.as_ref()).unwrap();
//            let coin_data: Output = bincode::deserialize(v.as_ref()).unwrap();
//            value_sum += coin_data.value;
//            coins_to_use.push(Input {
//                coin: coin_id,
//                value: coin_data.value,
//                owner: coin_data.recipient,
//            }); // coins that will be used for this transaction
//            if value_sum >= value {
//                // if we already have enough money, break
//                break;
//            }
//        }
//        if value_sum < value {
//            // we don't have enough money in wallet
//            return Err(WalletError::InsufficientBalance);
//        }
//        // if we have enough money in our wallet, create tx
//        // remove used coin from wallet
//        self.apply_diff(&vec![], &coins_to_use)?;
//
//        // create the output
//        let mut output = vec![Output { recipient, value }];
//        if value_sum > value {
//            // transfer the remaining value back to self
//            let recipient = self.addresses()?[0];
//            output.push(Output {
//                recipient,
//                value: value_sum - value,
//            });
//        }
//
//        let mut owners: Vec<Address> = coins_to_use.iter().map(|input|input.owner).collect();
//        let unsigned = Transaction {
//            input: coins_to_use,
//            output: output,
//            authorization: vec![],
//            hash: RefCell::new(None),
//        };
//        let mut authorization = vec![];
//        owners.sort_unstable();
//        owners.dedup();
//        for owner in owners.iter() {
//            let keypair = self.keypair(&owner)?;
//            authorization.push(Authorization {
//                pubkey: keypair.public_key(),
//                signature: unsigned.sign(&keypair),
//            });
//        }
//        self.counter.fetch_sub(unsigned.input.len(), Ordering::Relaxed);
//        Ok(Transaction {
//            authorization,
//            ..unsigned
//        })
//    }
}


#[derive(Debug)]
pub enum WalletError {
    InsufficientBalance,
    MissingKeyPair,
    DBError(lmdb::Error),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WalletError::InsufficientBalance => write!(f, "insufficient balance"),
            WalletError::MissingKeyPair => write!(f, "missing key pair for the requested address"),
            WalletError::DBError(ref e) => e.fmt(f),
        }
    }
}

impl error::Error for WalletError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            WalletError::DBError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<lmdb::Error> for WalletError {
    fn from(err: lmdb::Error) -> WalletError {
        WalletError::DBError(err)
    }
}