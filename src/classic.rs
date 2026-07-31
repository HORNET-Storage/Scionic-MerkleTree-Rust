use crate::encoding::sha256;
use crate::{Error, Result};
use std::collections::BTreeMap;

pub type Digest = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    siblings: Vec<Digest>,
    path: u32,
}

impl MerkleProof {
    pub fn siblings(&self) -> &[Digest] {
        &self.siblings
    }

    pub fn path(&self) -> u32 {
        self.path
    }

    pub(crate) fn from_parts(siblings: Vec<Digest>, path: u32) -> Result<Self> {
        if siblings.len() > u32::BITS as usize {
            return Err(Error::MerklePathTooDeep {
                depth: siblings.len(),
            });
        }
        Ok(Self { siblings, path })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassicMerkleTree {
    root: Digest,
    leaf_hashes: Vec<Digest>,
    proofs: Vec<MerkleProof>,
    depth: usize,
    keys: Vec<String>,
}

impl ClassicMerkleTree {
    pub fn build<I, K, V>(blocks: I) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<Vec<u8>>,
    {
        let mut sorted = BTreeMap::<String, Vec<u8>>::new();
        for (key, value) in blocks {
            sorted.insert(key.into(), value.into());
        }
        let count = sorted.len();
        if count <= 1 {
            return Err(Error::InvalidMerkleLeafCount { count });
        }
        let depth = (usize::BITS - (count - 1).leading_zeros()) as usize;
        if depth > u32::BITS as usize {
            return Err(Error::MerklePathTooDeep { depth });
        }
        let keys: Vec<String> = sorted.keys().cloned().collect();
        let leaf_hashes: Vec<Digest> = sorted.values().map(|value| sha256(value)).collect();
        let mut proofs = vec![
            MerkleProof {
                siblings: Vec::with_capacity(depth),
                path: 0
            };
            count
        ];
        let mut current = leaf_hashes.clone();
        let mut level = 0_usize;
        let mut group_size = 1_usize;
        while current.len() > 1 {
            if current.len() % 2 != 0 {
                let last = *current.last().expect("non-empty level");
                current.push(last);
            }
            let mut parents = Vec::with_capacity(current.len() / 2);
            for pair_index in 0..(current.len() / 2) {
                let left_node = current[pair_index * 2];
                let right_node = current[pair_index * 2 + 1];
                let left_start = pair_index * 2 * group_size;
                let left_end = (left_start + group_size).min(count);
                for proof in &mut proofs[left_start..left_end] {
                    proof.path |= 1_u32 << level;
                    proof.siblings.push(right_node);
                }
                let right_start = left_start + group_size;
                let right_end = (right_start + group_size).min(count);
                if right_start < count {
                    for proof in &mut proofs[right_start..right_end] {
                        proof.siblings.push(left_node);
                    }
                }
                parents.push(hash_pair(&left_node, &right_node));
            }
            current = parents;
            group_size = group_size
                .checked_mul(2)
                .ok_or(Error::MerklePathTooDeep { depth: level + 1 })?;
            level += 1;
        }
        Ok(Self {
            root: current[0],
            leaf_hashes,
            proofs,
            depth,
            keys,
        })
    }

    pub fn root(&self) -> &Digest {
        &self.root
    }

    pub fn leaf_hashes(&self) -> &[Digest] {
        &self.leaf_hashes
    }

    pub fn proofs(&self) -> &[MerkleProof] {
        &self.proofs
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    pub fn index_for_key(&self, key: &str) -> Option<usize> {
        self.keys
            .binary_search_by(|candidate| candidate.as_str().cmp(key))
            .ok()
    }

    pub fn proof_for_key(&self, key: &str) -> Result<&MerkleProof> {
        self.index_for_key(key)
            .map(|index| &self.proofs[index])
            .ok_or_else(|| Error::MissingMerkleKey {
                key: key.to_owned(),
            })
    }

    pub fn verify(&self, serialized_block: &[u8], proof: &MerkleProof) -> Result<()> {
        Self::verify_against(serialized_block, proof, &self.root)
    }

    pub fn verify_against(
        serialized_block: &[u8],
        proof: &MerkleProof,
        root: &Digest,
    ) -> Result<()> {
        let mut result = sha256(serialized_block);
        let mut path = proof.path;
        for sibling in &proof.siblings {
            result = if path & 1 == 1 {
                hash_pair(&result, sibling)
            } else {
                hash_pair(sibling, &result)
            };
            path >>= 1;
        }
        if &result == root {
            Ok(())
        } else {
            Err(Error::ProofVerificationFailed)
        }
    }
}

fn hash_pair(left: &Digest, right: &Digest) -> Digest {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    sha256(&bytes)
}
