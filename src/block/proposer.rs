extern crate bincode;
extern crate ring;

use super::block_header;
use super::hash;
use super::hash::Hashable;
use super::transaction;
use super::Block;

pub struct ProposerBlock {
    pub header: block_header::BlockHeader,
    pub transactions: Vec<transaction::Transaction>,
    pub metadata: ProposerMetadata,
}

impl Block for ProposerBlock {
    fn header(&self) -> &block_header::BlockHeader {
        return &self.header;
    }

    fn hash(&self) -> hash::Hash {
        return self.header.hash();
    }
}

pub struct ProposerMetadata {
    pub level_cert: hash::Hash,
    pub ref_links: Vec<hash::Hash>,
}

impl std::fmt::Display for ProposerMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{{\n")?;
        write!(f, "  level cert: {}\n", self.level_cert)?;
        write!(f, "  reference links: [\n")?;
        for r in &self.ref_links {
            write!(f, "    {},\n", r)?;
        }
        write!(f, "  ]\n",)?;
        write!(f, "}}")
    }
}

impl hash::Hashable for ProposerMetadata {
    fn hash(&self) -> hash::Hash {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        let serialized = bincode::serialize(&self.level_cert).unwrap();
        ctx.update(&serialized);
        for r in &self.ref_links {
            let serialized = bincode::serialize(&r).unwrap();
            ctx.update(&serialized);
        }
        let digest = ctx.finish();
        let mut raw_hash: [u8; 32] = [0; 32];
        raw_hash[0..32].clone_from_slice(digest.as_ref());
        return raw_hash.into();
    }
}

#[cfg(test)]
mod tests {
    use super::super::block_header;
    use super::super::hash;
    use super::super::hash::Hashable;
    use super::super::Block;
    use super::ProposerBlock;
    use super::ProposerMetadata;

    macro_rules! fake_proposer {
        () => {
            ProposerBlock {
                header: block_header::BlockHeader {
                    voter_hash: hash::Hash([1; 32]),
                    proposal_hash: hash::Hash([2; 32]),
                    transactions_hash: hash::Hash([3; 32]),
                    nonce: 12345,
                },
                transactions: vec![],
                metadata: ProposerMetadata {
                    level_cert: hash::Hash(hex!(
                        "0102030405060708010203040506070801020304050607080102030405060708"
                    )),
                    ref_links: vec![],
                },
            }
        };
    }

    #[test]
    fn metadata_hash() {
        let metadata = ProposerMetadata {
            level_cert: hash::Hash(hex!(
                "0102030401020304010203040102030401020304010203040102030401020304"
            )),
            ref_links: vec![
                hash::Hash(hex!(
                    "0102030405060504010203040506050401020304050605040102030405060504"
                )),
                hash::Hash(hex!(
                    "0403020104030201040302010403020104030201040302010403020104030201"
                )),
            ],
        };
        let hash = metadata.hash();
        let should_be = hash::Hash(hex!(
            "4062181720a6bf68005ce3f421566d725af5ca2b58175e305536f74be44ee71d"
        ));
        assert_eq!(hash, should_be);
    }

    #[test]
    fn block_hash() {
        let block = fake_proposer!();
        assert_eq!(
            block.hash(),
            hash::Hash(hex!(
                "29e6703a080f122e9ac455aedfbe9bd1974492df74f88ad970c07b824d4ea292"
            ))
        );
    }
}