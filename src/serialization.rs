use crate::classic::{Digest, MerkleProof};
use crate::dag::{Cid, ClassicTreeBranch, Dag, DagLeaf, Metadata};
use crate::encoding::{
    base64_standard, base64_standard_decode, cbor_decode_shared, cbor_encode, cbor_encode_into,
    sorted_wire_map, CborValue, KeyOrder,
};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(crate) struct WireKey {
    pub(crate) field: &'static str,
    pub(crate) canonical: &'static str,
    pub(crate) spellings: &'static [&'static str],
}

impl WireKey {
    pub(crate) const fn new(
        field: &'static str,
        canonical: &'static str,
        spellings: &'static [&'static str],
    ) -> Self {
        Self {
            field,
            canonical,
            spellings,
        }
    }
}

static DAG_ROOT: WireKey = WireKey::new("DAG.Root", "Root", &["Root", "root"]);
static DAG_LEAFS: WireKey = WireKey::new("DAG.Leafs", "Leafs", &["Leafs", "leafs"]);
static LEAF_HASH: WireKey = WireKey::new("DagLeaf.Hash", "Hash", &["Hash", "hash"]);
static LEAF_ITEM_NAME: WireKey =
    WireKey::new("DagLeaf.ItemName", "ItemName", &["ItemName", "itemName"]);
static LEAF_TYPE: WireKey = WireKey::new("DagLeaf.Type", "Type", &["Type", "type"]);
static LEAF_CONTENT_HASH: WireKey = WireKey::new(
    "DagLeaf.ContentHash",
    "ContentHash",
    &["ContentHash", "contentHash"],
);
static LEAF_CONTENT: WireKey = WireKey::new("DagLeaf.Content", "Content", &["Content", "content"]);
static LEAF_CLASSIC_ROOT: WireKey = WireKey::new(
    "DagLeaf.ClassicMerkleRoot",
    "ClassicMerkleRoot",
    &["ClassicMerkleRoot", "classicMerkleRoot"],
);
static LEAF_CURRENT_LINK_COUNT: WireKey = WireKey::new(
    "DagLeaf.CurrentLinkCount",
    "CurrentLinkCount",
    &["CurrentLinkCount", "currentLinkCount"],
);
static LEAF_COUNT: WireKey = WireKey::new(
    "DagLeaf.LeafCount",
    "LeafCount",
    &["LeafCount", "leafCount"],
);
static LEAF_CONTENT_SIZE: WireKey = WireKey::new(
    "DagLeaf.ContentSize",
    "ContentSize",
    &["ContentSize", "contentSize"],
);
static LEAF_DAG_SIZE: WireKey = WireKey::new("DagLeaf.DagSize", "DagSize", &["DagSize", "dagSize"]);
static LEAF_LINKS: WireKey = WireKey::new("DagLeaf.Links", "Links", &["Links", "links"]);
static LEAF_ADDITIONAL_DATA: WireKey = WireKey::new(
    "DagLeaf.AdditionalData",
    "AdditionalData",
    &["AdditionalData", "additionalData"],
);
static LEAF_STORED_PROOFS: WireKey = WireKey::new(
    "DagLeaf.stored_proofs",
    "stored_proofs",
    &["stored_proofs", "storedProofs"],
);
static BRANCH_LEAF: WireKey = WireKey::new("ClassicTreeBranch.Leaf", "Leaf", &["Leaf", "leaf"]);
static BRANCH_PROOF: WireKey =
    WireKey::new("ClassicTreeBranch.Proof", "Proof", &["Proof", "proof"]);
static PROOF_SIBLINGS: WireKey = WireKey::new(
    "MerkleProof.Siblings",
    "Siblings",
    &["Siblings", "siblings"],
);
static PROOF_PATH: WireKey = WireKey::new("MerkleProof.Path", "Path", &["Path", "path"]);

#[cfg(test)]
static ALL_WIRE_KEYS: [&WireKey; 19] = [
    &DAG_ROOT,
    &DAG_LEAFS,
    &LEAF_HASH,
    &LEAF_ITEM_NAME,
    &LEAF_TYPE,
    &LEAF_CONTENT_HASH,
    &LEAF_CONTENT,
    &LEAF_CLASSIC_ROOT,
    &LEAF_CURRENT_LINK_COUNT,
    &LEAF_COUNT,
    &LEAF_CONTENT_SIZE,
    &LEAF_DAG_SIZE,
    &LEAF_LINKS,
    &LEAF_ADDITIONAL_DATA,
    &LEAF_STORED_PROOFS,
    &BRANCH_LEAF,
    &BRANCH_PROOF,
    &PROOF_SIBLINGS,
    &PROOF_PATH,
];

impl Dag {
    pub fn to_json(&self) -> Result<Vec<u8>> {
        // JSON is not CBOR with different punctuation. Go reaches it through
        // encoding/json, which sorts map keys bytewise with no length term, so
        // the dynamic maps have to be rebuilt under KeyOrder::Json instead of
        // reusing the CBOR-ordered tree. Everything else about the two trees --
        // key names, struct field order, which values are null -- is identical.
        let mut output = String::new();
        write_json(&dag_wire_value(self, KeyOrder::Json), &mut output, 0)?;
        Ok(output.into_bytes())
    }

    pub fn from_json(input: &[u8]) -> Result<Self> {
        let value = parse_json(input)?;
        let wire = json_dag_to_cbor(&value)?;
        dag_from_wire_value(&wire)
    }

    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        Ok(cbor_encode(&dag_wire_value(self, KeyOrder::Cbor)))
    }

    /// Encodes the DAG into a buffer the caller owns, appending to it.
    ///
    /// Byte-for-byte what [`Dag::to_cbor`] produces; the only difference is who
    /// owns the buffer. That matters more than it sounds: on the 18.25 MiB
    /// benchmark corpus the encoder itself runs at the alloc-plus-memcpy floor,
    /// so roughly three quarters of `to_cbor`'s cost is allocating a fresh 19 MB
    /// buffer and taking the page faults on it. Reusing one buffer across encodes
    /// measures 2.0ms against 4.9ms -- 2.4x -- without changing a single output
    /// byte.
    ///
    /// Callers that encode once should keep using `to_cbor` -- it is the same
    /// work, and an owned `Vec` is the friendlier return.
    pub fn to_cbor_into(&self, output: &mut Vec<u8>) -> Result<()> {
        cbor_encode_into(&dag_wire_value(self, KeyOrder::Cbor), output);
        Ok(())
    }

    pub fn from_cbor(input: &[u8]) -> Result<Self> {
        let value = cbor_decode_shared(input)?;
        dag_from_wire_value(&value)
    }
}

fn dag_wire_value(dag: &Dag, order: KeyOrder) -> CborValue {
    let leaves = dag
        .leaves()
        .iter()
        .map(|(cid, leaf)| (cid.to_string(), leaf_wire_value(leaf, order)))
        .collect();
    CborValue::Map(vec![
        ("Root".to_owned(), CborValue::Text(dag.root().to_string())),
        // Leafs is a genuine dynamic map (Go: SerializableDag.Leafs), so it
        // sorts. The two pairs around it are struct fields and must not.
        ("Leafs".to_owned(), sorted_wire_map(leaves, order)),
    ])
}

pub(crate) fn leaf_wire_value(leaf: &DagLeaf, order: KeyOrder) -> CborValue {
    let mut pairs = vec![
        ("Hash".to_owned(), CborValue::Text(leaf.cid().to_string())),
        (
            "ItemName".to_owned(),
            CborValue::Text(leaf.item_name().to_owned()),
        ),
        (
            "Type".to_owned(),
            CborValue::Text(leaf.leaf_type().as_str().to_owned()),
        ),
        (
            "ContentHash".to_owned(),
            optional_bytes(leaf.content_hash().map(Digest::as_slice)),
        ),
        (
            "Content".to_owned(),
            // Shared rather than copied: content is the only field big enough
            // for the extra pass to matter, and it is already behind an `Arc`.
            optional_shared_bytes(leaf.content_arc()),
        ),
        (
            "ClassicMerkleRoot".to_owned(),
            optional_bytes(leaf.classic_merkle_root_wire()),
        ),
        (
            "CurrentLinkCount".to_owned(),
            CborValue::Unsigned(leaf.current_link_count() as u64),
        ),
        (
            "LeafCount".to_owned(),
            CborValue::Unsigned(leaf.leaf_count()),
        ),
        (
            "ContentSize".to_owned(),
            CborValue::Unsigned(leaf.content_size()),
        ),
        ("DagSize".to_owned(), CborValue::Unsigned(leaf.dag_size())),
        (
            "Links".to_owned(),
            CborValue::Array(
                leaf.links()
                    .iter()
                    .map(|cid| CborValue::Text(cid.to_string()))
                    .collect(),
            ),
        ),
        (
            "AdditionalData".to_owned(),
            // The only wire map keyed by arbitrary strings, and therefore the
            // only one where the CBOR and JSON comparators can actually differ.
            sorted_wire_map(
                leaf.additional_data()
                    .iter()
                    .map(|(key, value)| (key.clone(), CborValue::Text(value.clone())))
                    .collect(),
                order,
            ),
        ),
    ];
    if !leaf.proofs().is_empty() {
        pairs.push((
            "stored_proofs".to_owned(),
            sorted_wire_map(
                leaf.proofs()
                    .iter()
                    .map(|(key, branch)| (key.to_string(), proof_wire_value(branch)))
                    .collect(),
                order,
            ),
        ));
    }
    CborValue::Map(pairs)
}

pub(crate) fn proof_wire_value(branch: &ClassicTreeBranch) -> CborValue {
    CborValue::Map(vec![
        (
            "Leaf".to_owned(),
            CborValue::Text(branch.child().to_string()),
        ),
        (
            "Proof".to_owned(),
            CborValue::Map(vec![
                (
                    "Siblings".to_owned(),
                    CborValue::Array(
                        branch
                            .proof()
                            .siblings()
                            .iter()
                            .map(|sibling| CborValue::Bytes(sibling.to_vec()))
                            .collect(),
                    ),
                ),
                (
                    "Path".to_owned(),
                    CborValue::Unsigned(u64::from(branch.proof().path())),
                ),
            ]),
        ),
    ])
}

fn optional_bytes(value: Option<&[u8]>) -> CborValue {
    value.map_or(CborValue::Null, |bytes| CborValue::Bytes(bytes.to_vec()))
}

/// Wire form of an optional shared payload.
///
/// `None` and `Some(empty)` stay distinct -- the first encodes as CBOR null and
/// the second as a zero-length byte string -- because that distinction is
/// hash-visible and Go draws it too.
fn optional_shared_bytes(value: Option<Arc<Vec<u8>>>) -> CborValue {
    value.map_or(CborValue::Null, CborValue::SharedBytes)
}

fn dag_from_wire_value(value: &CborValue) -> Result<Dag> {
    let map = cbor_map(value, "DAG")?;
    let root_text = cbor_required_text(cbor_get(map, &DAG_ROOT)?, "Root")?;
    let root = Cid::parse(root_text)?;
    let leaf_map = cbor_map(
        cbor_get(map, &DAG_LEAFS)?.ok_or_else(|| invalid("missing Leafs"))?,
        "Leafs",
    )?;
    let mut leaves = BTreeMap::new();
    for (key_text, leaf_value) in leaf_map {
        let key = Cid::parse(key_text)?;
        let leaf = decode_leaf(&key, leaf_value, key == root)?;
        if leaf.cid() != &key {
            return Err(Error::CidKeyMismatch {
                key: key.to_string(),
                cid: leaf.cid().to_string(),
            });
        }
        leaves.insert(key, leaf);
    }
    Dag::from_parts(root, leaves)
}

pub(crate) fn decode_leaf(
    key: &Cid,
    value: &CborValue,
    preserve_counters: bool,
) -> Result<DagLeaf> {
    let map = cbor_map(value, "leaf")?;
    let hash = Cid::parse(cbor_required_text(cbor_get(map, &LEAF_HASH)?, "Hash")?)?;
    if &hash != key {
        return Err(Error::CidKeyMismatch {
            key: key.to_string(),
            cid: hash.to_string(),
        });
    }
    let item_name = cbor_optional_text(cbor_get(map, &LEAF_ITEM_NAME)?)?
        .unwrap_or_default()
        .to_owned();
    let leaf_type = cbor_optional_text(cbor_get(map, &LEAF_TYPE)?)?
        .unwrap_or("file")
        .parse()?;
    let content_hash = match cbor_optional_bytes(cbor_get(map, &LEAF_CONTENT_HASH)?)? {
        Some(bytes) => Some(digest_from_bytes(bytes, "ContentHash")?),
        None => None,
    };
    let content = cbor_optional_shared_bytes(cbor_get(map, &LEAF_CONTENT)?)?;
    let classic_merkle_root =
        cbor_optional_bytes(cbor_get(map, &LEAF_CLASSIC_ROOT)?)?.map(<[u8]>::to_vec);
    let current_link_count = usize::try_from(
        cbor_optional_unsigned(cbor_get(map, &LEAF_CURRENT_LINK_COUNT)?)?.unwrap_or(0),
    )
    .map_err(|_| Error::SizeOverflow {
        field: "CurrentLinkCount",
    })?;
    let wire_leaf_count = cbor_optional_unsigned(cbor_get(map, &LEAF_COUNT)?)?.unwrap_or(0);
    let wire_content_size =
        cbor_optional_unsigned(cbor_get(map, &LEAF_CONTENT_SIZE)?)?.unwrap_or(0);
    let wire_dag_size = cbor_optional_unsigned(cbor_get(map, &LEAF_DAG_SIZE)?)?.unwrap_or(0);
    let links = decode_links(cbor_get(map, &LEAF_LINKS)?)?;
    let additional_data = decode_metadata(cbor_get(map, &LEAF_ADDITIONAL_DATA)?)?;
    let proofs = decode_proofs(cbor_get(map, &LEAF_STORED_PROOFS)?, true)?;
    Ok(DagLeaf::from_parts(
        hash,
        item_name,
        leaf_type,
        content_hash,
        content,
        classic_merkle_root,
        current_link_count,
        if preserve_counters {
            wire_leaf_count
        } else {
            0
        },
        if preserve_counters {
            wire_content_size
        } else {
            0
        },
        if preserve_counters { wire_dag_size } else { 0 },
        links,
        additional_data,
        proofs,
    ))
}

fn decode_links(value: Option<&CborValue>) -> Result<Vec<Cid>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if matches!(value, CborValue::Null) {
        return Ok(Vec::new());
    }
    let CborValue::Array(values) = value else {
        return Err(invalid("Links is not an array"));
    };
    values
        .iter()
        .map(|value| Cid::parse(cbor_text(value, "Links entry")?))
        .collect()
}

fn decode_metadata(value: Option<&CborValue>) -> Result<Metadata> {
    let Some(value) = value else {
        return Ok(Metadata::new());
    };
    if matches!(value, CborValue::Null) {
        return Ok(Metadata::new());
    }
    cbor_map(value, "AdditionalData")?
        .iter()
        .map(|(key, value)| Ok((key.clone(), cbor_text(value, "metadata value")?.to_owned())))
        .collect()
}

pub(crate) fn decode_proofs(
    value: Option<&CborValue>,
    enforce_key_binding: bool,
) -> Result<BTreeMap<Cid, ClassicTreeBranch>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    if matches!(value, CborValue::Null) {
        return Ok(BTreeMap::new());
    }
    let mut proofs = BTreeMap::new();
    for (key_text, branch_value) in cbor_map(value, "stored_proofs")? {
        let key = Cid::parse(key_text)?;
        let branch_map = cbor_map(branch_value, "stored proof")?;
        let child = Cid::parse(cbor_required_text(
            cbor_get(branch_map, &BRANCH_LEAF)?,
            "stored proof Leaf",
        )?)?;
        if enforce_key_binding && key != child {
            return Err(Error::ProofKeyMismatch {
                key: key.to_string(),
                child: child.to_string(),
            });
        }
        let proof_value = cbor_get(branch_map, &BRANCH_PROOF)?
            .ok_or_else(|| invalid("stored proof is missing Proof"))?;
        let proof_map = cbor_map(proof_value, "Proof")?;
        let siblings = decode_siblings(cbor_get(proof_map, &PROOF_SIBLINGS)?)?;
        let path =
            u32::try_from(cbor_optional_unsigned(cbor_get(proof_map, &PROOF_PATH)?)?.unwrap_or(0))
                .map_err(|_| invalid("proof Path exceeds u32"))?;
        let proof = MerkleProof::from_parts(siblings, path)?;
        proofs.insert(key, ClassicTreeBranch::new(child, proof));
    }
    Ok(proofs)
}

fn decode_siblings(value: Option<&CborValue>) -> Result<Vec<Digest>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let CborValue::Array(values) = value else {
        return Err(invalid("proof Siblings is not an array"));
    };
    values
        .iter()
        .map(|value| match value {
            CborValue::Bytes(bytes) => digest_from_bytes(bytes, "proof sibling"),
            CborValue::SharedBytes(bytes) => digest_from_bytes(bytes, "proof sibling"),
            _ => Err(invalid("proof sibling is not bytes")),
        })
        .collect()
}

fn digest_from_bytes(bytes: &[u8], field: &'static str) -> Result<Digest> {
    bytes.try_into().map_err(|_| Error::InvalidData {
        detail: format!("{field} must contain exactly 32 bytes"),
    })
}

pub(crate) fn cbor_map<'a>(
    value: &'a CborValue,
    field: &'static str,
) -> Result<&'a [(String, CborValue)]> {
    match value {
        CborValue::Map(pairs) => Ok(pairs),
        _ => Err(Error::InvalidData {
            detail: format!("{field} is not a map"),
        }),
    }
}

pub(crate) fn lookup_unique<'a, T>(
    pairs: &'a [(String, T)],
    key: &WireKey,
) -> Result<Option<&'a T>> {
    let mut found: Option<(&str, &T)> = None;
    for (raw, value) in pairs {
        if key.spellings.iter().any(|spelling| raw == spelling) {
            if let Some((first, _)) = found {
                return Err(Error::AmbiguousFieldSpellings {
                    field: key.field,
                    first: first.to_owned(),
                    second: raw.clone(),
                });
            }
            found = Some((raw, value));
        }
    }
    Ok(found.map(|(_, value)| value))
}

pub(crate) fn cbor_get<'a>(
    pairs: &'a [(String, CborValue)],
    key: &WireKey,
) -> Result<Option<&'a CborValue>> {
    lookup_unique(pairs, key)
}

pub(crate) fn cbor_text<'a>(value: &'a CborValue, field: &'static str) -> Result<&'a str> {
    match value {
        CborValue::Text(text) => Ok(text),
        _ => Err(Error::InvalidData {
            detail: format!("{field} is not text"),
        }),
    }
}

pub(crate) fn cbor_required_text<'a>(
    value: Option<&'a CborValue>,
    field: &'static str,
) -> Result<&'a str> {
    cbor_text(
        value.ok_or_else(|| Error::InvalidData {
            detail: format!("missing {field}"),
        })?,
        field,
    )
}

pub(crate) fn cbor_optional_text(value: Option<&CborValue>) -> Result<Option<&str>> {
    match value {
        None | Some(CborValue::Null) => Ok(None),
        Some(CborValue::Text(text)) => Ok(Some(text)),
        _ => Err(invalid("expected text or null")),
    }
}

pub(crate) fn cbor_optional_bytes(value: Option<&CborValue>) -> Result<Option<&[u8]>> {
    match value {
        None | Some(CborValue::Null) => Ok(None),
        Some(CborValue::Bytes(bytes)) => Ok(Some(bytes)),
        Some(CborValue::SharedBytes(bytes)) => Ok(Some(bytes)),
        _ => Err(invalid("expected bytes or null")),
    }
}

/// An optional byte string as a shared handle, without copying it when the
/// decoder already allocated one.
///
/// `Bytes` still has to be copied -- there is nothing to share -- but the
/// decoder produces `SharedBytes`, so the common path is a refcount bump.
/// Accepting both keeps this correct for a value tree assembled by hand.
pub(crate) fn cbor_optional_shared_bytes(
    value: Option<&CborValue>,
) -> Result<Option<Arc<Vec<u8>>>> {
    match value {
        None | Some(CborValue::Null) => Ok(None),
        Some(CborValue::SharedBytes(bytes)) => Ok(Some(Arc::clone(bytes))),
        Some(CborValue::Bytes(bytes)) => Ok(Some(Arc::new(bytes.clone()))),
        _ => Err(invalid("expected bytes or null")),
    }
}

pub(crate) fn cbor_optional_unsigned(value: Option<&CborValue>) -> Result<Option<u64>> {
    match value {
        None | Some(CborValue::Null) => Ok(None),
        Some(CborValue::Unsigned(number)) => Ok(Some(*number)),
        _ => Err(invalid("expected an unsigned integer")),
    }
}

fn invalid(detail: impl Into<String>) -> Error {
    Error::InvalidData {
        detail: detail.into(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

pub(crate) fn parse_json(input: &[u8]) -> Result<JsonValue> {
    JsonParser::new(input).parse()
}

fn json_dag_to_cbor(value: &JsonValue) -> Result<CborValue> {
    let object = json_object(value, "DAG")?;
    let root = json_required_string(json_get(object, &DAG_ROOT)?, "Root")?;
    let leaves = json_object(
        json_get(object, &DAG_LEAFS)?.ok_or_else(|| invalid_json("missing Leafs"))?,
        "Leafs",
    )?;
    Ok(CborValue::Map(vec![
        ("Root".to_owned(), CborValue::Text(root.to_owned())),
        (
            "Leafs".to_owned(),
            CborValue::Map(
                leaves
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), json_leaf_to_cbor(value)?)))
                    .collect::<Result<Vec<_>>>()?,
            ),
        ),
    ]))
}

pub(crate) fn json_leaf_to_cbor(value: &JsonValue) -> Result<CborValue> {
    let object = json_object(value, "leaf")?;
    let mut pairs = Vec::new();
    copy_json_text(object, &LEAF_HASH, &mut pairs)?;
    copy_json_text(object, &LEAF_ITEM_NAME, &mut pairs)?;
    copy_json_text(object, &LEAF_TYPE, &mut pairs)?;
    copy_json_bytes(object, &LEAF_CONTENT_HASH, &mut pairs)?;
    copy_json_bytes(object, &LEAF_CONTENT, &mut pairs)?;
    copy_json_bytes(object, &LEAF_CLASSIC_ROOT, &mut pairs)?;
    copy_json_number(object, &LEAF_CURRENT_LINK_COUNT, &mut pairs)?;
    copy_json_number(object, &LEAF_COUNT, &mut pairs)?;
    copy_json_number(object, &LEAF_CONTENT_SIZE, &mut pairs)?;
    copy_json_number(object, &LEAF_DAG_SIZE, &mut pairs)?;

    if let Some(value) = json_get(object, &LEAF_LINKS)? {
        let converted = match value {
            JsonValue::Null => CborValue::Null,
            JsonValue::Array(values) => CborValue::Array(
                values
                    .iter()
                    .map(|value| {
                        Ok(CborValue::Text(
                            json_string(value, "Links entry")?.to_owned(),
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => return Err(invalid_json("Links is not an array")),
        };
        pairs.push((LEAF_LINKS.canonical.to_owned(), converted));
    }

    if let Some(value) = json_get(object, &LEAF_ADDITIONAL_DATA)? {
        let converted = match value {
            JsonValue::Null => CborValue::Null,
            JsonValue::Object(values) => CborValue::Map(
                values
                    .iter()
                    .map(|(key, value)| {
                        Ok((
                            key.clone(),
                            CborValue::Text(json_string(value, "metadata value")?.to_owned()),
                        ))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => return Err(invalid_json("AdditionalData is not an object")),
        };
        pairs.push((LEAF_ADDITIONAL_DATA.canonical.to_owned(), converted));
    }

    if let Some(value) = json_get(object, &LEAF_STORED_PROOFS)? {
        let converted = match value {
            JsonValue::Null => CborValue::Null,
            JsonValue::Object(values) => CborValue::Map(
                values
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), json_proof_to_cbor(value)?)))
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => return Err(invalid_json("stored_proofs is not an object")),
        };
        pairs.push((LEAF_STORED_PROOFS.canonical.to_owned(), converted));
    }
    Ok(CborValue::Map(pairs))
}

pub(crate) fn json_proof_to_cbor(value: &JsonValue) -> Result<CborValue> {
    let object = json_object(value, "stored proof")?;
    let child = json_required_string(json_get(object, &BRANCH_LEAF)?, "Leaf")?;
    let proof_value = json_get(object, &BRANCH_PROOF)?
        .ok_or_else(|| invalid_json("stored proof is missing Proof"))?;
    let proof_object = json_object(proof_value, "Proof")?;
    let siblings = match json_get(proof_object, &PROOF_SIBLINGS)? {
        None | Some(JsonValue::Null) => Vec::new(),
        Some(JsonValue::Array(values)) => values
            .iter()
            .map(|value| {
                Ok(CborValue::Bytes(base64_standard_decode(json_string(
                    value,
                    "proof sibling",
                )?)?))
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(invalid_json("proof Siblings is not an array")),
    };
    let path = match json_get(proof_object, &PROOF_PATH)? {
        None | Some(JsonValue::Null) => 0,
        Some(JsonValue::Number(value)) => *value,
        _ => return Err(invalid_json("proof Path is not an unsigned integer")),
    };
    Ok(CborValue::Map(vec![
        ("Leaf".to_owned(), CborValue::Text(child.to_owned())),
        (
            "Proof".to_owned(),
            CborValue::Map(vec![
                ("Siblings".to_owned(), CborValue::Array(siblings)),
                ("Path".to_owned(), CborValue::Unsigned(path)),
            ]),
        ),
    ]))
}

fn copy_json_text(
    object: &[(String, JsonValue)],
    key: &WireKey,
    output: &mut Vec<(String, CborValue)>,
) -> Result<()> {
    if let Some(value) = json_get(object, key)? {
        output.push((
            key.canonical.to_owned(),
            match value {
                JsonValue::Null => CborValue::Null,
                JsonValue::String(text) => CborValue::Text(text.clone()),
                _ => {
                    return Err(invalid_json(format!("{} is not text", key.canonical)));
                }
            },
        ));
    }
    Ok(())
}

fn copy_json_bytes(
    object: &[(String, JsonValue)],
    key: &WireKey,
    output: &mut Vec<(String, CborValue)>,
) -> Result<()> {
    if let Some(value) = json_get(object, key)? {
        output.push((
            key.canonical.to_owned(),
            match value {
                JsonValue::Null => CborValue::Null,
                JsonValue::String(text) => CborValue::Bytes(base64_standard_decode(text)?),
                _ => {
                    return Err(invalid_json(format!(
                        "{} is not base64 text",
                        key.canonical
                    )));
                }
            },
        ));
    }
    Ok(())
}

fn copy_json_number(
    object: &[(String, JsonValue)],
    key: &WireKey,
    output: &mut Vec<(String, CborValue)>,
) -> Result<()> {
    if let Some(value) = json_get(object, key)? {
        output.push((
            key.canonical.to_owned(),
            match value {
                JsonValue::Null => CborValue::Null,
                JsonValue::Number(number) => CborValue::Unsigned(*number),
                _ => {
                    return Err(invalid_json(format!(
                        "{} is not an unsigned integer",
                        key.canonical
                    )));
                }
            },
        ));
    }
    Ok(())
}

pub(crate) fn json_object<'a>(
    value: &'a JsonValue,
    field: &'static str,
) -> Result<&'a [(String, JsonValue)]> {
    match value {
        JsonValue::Object(values) => Ok(values),
        _ => Err(invalid_json(format!("{field} is not an object"))),
    }
}

pub(crate) fn json_get<'a>(
    object: &'a [(String, JsonValue)],
    key: &WireKey,
) -> Result<Option<&'a JsonValue>> {
    lookup_unique(object, key)
}

pub(crate) fn json_string<'a>(value: &'a JsonValue, field: &'static str) -> Result<&'a str> {
    match value {
        JsonValue::String(text) => Ok(text),
        _ => Err(invalid_json(format!("{field} is not text"))),
    }
}

pub(crate) fn json_required_string<'a>(
    value: Option<&'a JsonValue>,
    field: &'static str,
) -> Result<&'a str> {
    json_string(
        value.ok_or_else(|| invalid_json(format!("missing {field}")))?,
        field,
    )
}

fn invalid_json(detail: impl Into<String>) -> Error {
    Error::InvalidJson {
        detail: detail.into(),
    }
}

pub(crate) fn write_json(value: &CborValue, output: &mut String, depth: usize) -> Result<()> {
    match value {
        CborValue::Unsigned(number) => output.push_str(&number.to_string()),
        CborValue::Negative(_) => return Err(invalid("wire JSON cannot contain negatives")),
        CborValue::Bytes(bytes) => write_json_string(&base64_standard(bytes), output),
        CborValue::SharedBytes(bytes) => write_json_string(&base64_standard(bytes), output),
        CborValue::Text(text) => write_json_string(text, output),
        CborValue::Array(values) => {
            if values.is_empty() {
                output.push_str("[]");
            } else {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    output.push('\n');
                    write_indent(output, depth + 1);
                    write_json(value, output, depth + 1)?;
                    if index + 1 != values.len() {
                        output.push(',');
                    }
                }
                output.push('\n');
                write_indent(output, depth);
                output.push(']');
            }
        }
        CborValue::Map(pairs) => {
            if pairs.is_empty() {
                output.push_str("{}");
            } else {
                output.push('{');
                for (index, (key, value)) in pairs.iter().enumerate() {
                    output.push('\n');
                    write_indent(output, depth + 1);
                    write_json_string(key, output);
                    output.push_str(": ");
                    write_json(value, output, depth + 1)?;
                    if index + 1 != pairs.len() {
                        output.push(',');
                    }
                }
                output.push('\n');
                write_indent(output, depth);
                output.push('}');
            }
        }
        CborValue::Null => output.push_str("null"),
        CborValue::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
    }
    Ok(())
}

fn write_indent(output: &mut String, depth: usize) {
    for _ in 0..depth {
        output.push_str("  ");
    }
}

fn write_json_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '<' => output.push_str("\\u003c"),
            '>' => output.push_str("\\u003e"),
            '&' => output.push_str("\\u0026"),
            '\u{2028}' => output.push_str("\\u2028"),
            '\u{2029}' => output.push_str("\\u2029"),
            character if character <= '\u{1f}' => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

struct JsonParser<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn parse(mut self) -> Result<JsonValue> {
        self.skip_whitespace();
        let value = self.parse_value(0)?;
        self.skip_whitespace();
        if self.cursor != self.input.len() {
            return Err(invalid_json("trailing bytes after the top-level value"));
        }
        Ok(value)
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue> {
        if depth > 256 {
            return Err(invalid_json("maximum nesting depth exceeded"));
        }
        self.skip_whitespace();
        match self.peek() {
            Some(b'n') => {
                self.expect_literal(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(b't') => {
                self.expect_literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            Some(b'f') => {
                self.expect_literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'0'..=b'9') => self.parse_number().map(JsonValue::Number),
            Some(_) => Err(invalid_json("unexpected token")),
            None => Err(invalid_json("truncated input")),
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue> {
        self.expect_byte(b'[')?;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.consume(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.parse_value(depth)?);
            self.skip_whitespace();
            if self.consume(b']') {
                break;
            }
            self.expect_byte(b',')?;
        }
        Ok(JsonValue::Array(values))
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue> {
        self.expect_byte(b'{')?;
        self.skip_whitespace();
        let mut values = Vec::new();
        let mut keys = BTreeSet::new();
        if self.consume(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            if !keys.insert(key.clone()) {
                return Err(Error::DuplicateKey { key });
            }
            self.skip_whitespace();
            self.expect_byte(b':')?;
            let value = self.parse_value(depth)?;
            values.push((key, value));
            self.skip_whitespace();
            if self.consume(b'}') {
                break;
            }
            self.expect_byte(b',')?;
        }
        Ok(JsonValue::Object(values))
    }

    fn parse_number(&mut self) -> Result<u64> {
        let start = self.cursor;
        match self.peek() {
            Some(b'0') => {
                self.cursor += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(invalid_json("number has a leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.cursor += 1;
                }
            }
            _ => return Err(invalid_json("invalid number")),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(invalid_json("wire number must be an unsigned integer"));
        }
        std::str::from_utf8(&self.input[start..self.cursor])
            .map_err(|_| invalid_json("number is not UTF-8"))?
            .parse()
            .map_err(|_| invalid_json("unsigned integer overflows u64"))
    }

    fn parse_string(&mut self) -> Result<String> {
        self.expect_byte(b'"')?;
        let mut bytes = Vec::new();
        loop {
            let byte = self
                .take()
                .ok_or_else(|| invalid_json("truncated string"))?;
            match byte {
                b'"' => {
                    return String::from_utf8(bytes)
                        .map_err(|_| invalid_json("string is not valid UTF-8"));
                }
                b'\\' => {
                    let escaped = self
                        .take()
                        .ok_or_else(|| invalid_json("truncated string escape"))?;
                    match escaped {
                        b'"' | b'\\' | b'/' => bytes.push(escaped),
                        b'b' => bytes.push(0x08),
                        b'f' => bytes.push(0x0c),
                        b'n' => bytes.push(b'\n'),
                        b'r' => bytes.push(b'\r'),
                        b't' => bytes.push(b'\t'),
                        b'u' => {
                            let first = self.parse_hex_u16()?;
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                self.expect_byte(b'\\')?;
                                self.expect_byte(b'u')?;
                                let second = self.parse_hex_u16()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(invalid_json("invalid Unicode surrogate pair"));
                                }
                                0x1_0000
                                    + ((u32::from(first) - 0xd800) << 10)
                                    + (u32::from(second) - 0xdc00)
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err(invalid_json("lone low Unicode surrogate"));
                            } else {
                                u32::from(first)
                            };
                            let character = char::from_u32(scalar)
                                .ok_or_else(|| invalid_json("invalid Unicode scalar"))?;
                            let mut encoded = [0_u8; 4];
                            bytes.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                        }
                        _ => return Err(invalid_json("invalid string escape")),
                    }
                }
                0x00..=0x1f => return Err(invalid_json("unescaped control in string")),
                _ => bytes.push(byte),
            }
        }
    }

    fn parse_hex_u16(&mut self) -> Result<u16> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = match self.take() {
                Some(b'0'..=b'9') => self.input[self.cursor - 1] - b'0',
                Some(b'a'..=b'f') => self.input[self.cursor - 1] - b'a' + 10,
                Some(b'A'..=b'F') => self.input[self.cursor - 1] - b'A' + 10,
                _ => return Err(invalid_json("invalid Unicode escape")),
            };
            value = (value << 4) | u16::from(digit);
        }
        Ok(value)
    }

    fn expect_literal(&mut self, literal: &[u8]) -> Result<()> {
        let end = self
            .cursor
            .checked_add(literal.len())
            .ok_or_else(|| invalid_json("input offset overflow"))?;
        if self.input.get(self.cursor..end) != Some(literal) {
            return Err(invalid_json("invalid literal"));
        }
        self.cursor = end;
        Ok(())
    }

    fn expect_byte(&mut self, expected: u8) -> Result<()> {
        self.skip_whitespace();
        match self.take() {
            Some(actual) if actual == expected => Ok(()),
            _ => Err(invalid_json("unexpected delimiter")),
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        self.skip_whitespace();
        if self.peek() == Some(expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.cursor += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.cursor).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.cursor += 1;
        Some(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_wire_key_rejects_equal_or_unequal_alias_coexistence_in_both_orders() {
        for key in ALL_WIRE_KEYS {
            let canonical_cbor = vec![(key.canonical.to_owned(), CborValue::Unsigned(1))];
            let alias_cbor = vec![(key.spellings[1].to_owned(), CborValue::Unsigned(2))];
            assert!(cbor_get(&canonical_cbor, key).unwrap().is_some());
            assert!(cbor_get(&alias_cbor, key).unwrap().is_some());

            let canonical_json = vec![(key.canonical.to_owned(), JsonValue::Number(1))];
            let alias_json = vec![(key.spellings[1].to_owned(), JsonValue::Number(2))];
            assert!(json_get(&canonical_json, key).unwrap().is_some());
            assert!(json_get(&alias_json, key).unwrap().is_some());

            for reverse in [false, true] {
                for equal in [false, true] {
                    let mut cbor_pairs = vec![
                        (key.canonical.to_owned(), CborValue::Unsigned(1)),
                        (
                            key.spellings[1].to_owned(),
                            CborValue::Unsigned(if equal { 1 } else { 2 }),
                        ),
                    ];
                    let mut json_pairs = vec![
                        (key.canonical.to_owned(), JsonValue::Number(1)),
                        (
                            key.spellings[1].to_owned(),
                            JsonValue::Number(if equal { 1 } else { 2 }),
                        ),
                    ];
                    if reverse {
                        cbor_pairs.reverse();
                        json_pairs.reverse();
                    }
                    for error in [
                        cbor_get(&cbor_pairs, key).unwrap_err(),
                        json_get(&json_pairs, key).unwrap_err(),
                    ] {
                        match error {
                            Error::AmbiguousFieldSpellings {
                                field,
                                first,
                                second,
                            } => {
                                assert_eq!(field, key.field);
                                assert_eq!(first, cbor_pairs[0].0);
                                assert_eq!(second, cbor_pairs[1].0);
                            }
                            other => panic!("unexpected ambiguity error: {other}"),
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn flat_cbor_proof_objects_are_rejected() {
        let child = Cid::from_cbor(b"flat CBOR proof child");
        for (siblings_key, path_key) in [("Siblings", "Path"), ("siblings", "path")] {
            let flat = CborValue::Map(vec![(
                child.to_string(),
                CborValue::Map(vec![
                    ("Leaf".to_owned(), CborValue::Text(child.to_string())),
                    (siblings_key.to_owned(), CborValue::Array(Vec::new())),
                    (path_key.to_owned(), CborValue::Unsigned(0)),
                ]),
            )]);
            let error = match decode_proofs(Some(&flat), true) {
                Ok(_) => panic!("flat CBOR proof was accepted"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                Error::InvalidData { detail } if detail == "stored proof is missing Proof"
            ));
        }
    }

    #[test]
    fn flat_json_proof_objects_are_rejected() {
        let child = Cid::from_cbor(b"flat JSON proof child");
        for (siblings_key, path_key) in [("Siblings", "Path"), ("siblings", "path")] {
            let flat = JsonValue::Object(vec![
                ("Leaf".to_owned(), JsonValue::String(child.to_string())),
                (siblings_key.to_owned(), JsonValue::Array(Vec::new())),
                (path_key.to_owned(), JsonValue::Number(0)),
            ]);
            let error = match json_proof_to_cbor(&flat) {
                Ok(_) => panic!("flat JSON proof was accepted"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                Error::InvalidJson { detail } if detail == "stored proof is missing Proof"
            ));
        }
    }

    #[test]
    fn exact_duplicate_json_keys_remain_a_syntax_error() {
        assert!(matches!(
            parse_json(br#"{"Root":"a","Root":"b"}"#),
            Err(Error::DuplicateKey { key }) if key == "Root"
        ));
    }
}
