//! The vectors that the Rust, Go and Swift libraries share.
//!
//! `spec/vectors/manifest.json` holds trees with every one of their bytes,
//! parts of them as they are shown, requests and their answers, and forged
//! bytes that must be refused. This test makes all of it again from the
//! library and holds the committed file to it, byte for byte. A forged
//! vector goes into the file only once the library has refused it.
//!
//! When the format changes on purpose, run the tests once with
//! `SCIONIC_WRITE_VECTORS=1`, and read what changed in the files.

mod support;

use scionic_merkletree::{
    export, file_branch_frame, file_of, folder_branch_frame, folder_of, lookup, record_of, serve,
    Builder, ChunkRef, Chunking, Entry, ExtraData, FileBranch, FileList, FolderBranch, FolderList,
    Frame, Hash, MemoryStore, Record, Request, Responder, Root, Target,
};
use std::path::{Path, PathBuf};
use support::bytes;
use support::json::Json;

fn text(value: impl Into<String>) -> Json {
    Json::Text(value.into())
}

fn number(value: u64) -> Json {
    Json::Number(value.to_string())
}

fn object(members: Vec<(&str, Json)>) -> Json {
    Json::Object(
        members
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex(bytes: &[u8]) -> Json {
    text(to_hex(bytes))
}

fn as_number(value: &Json) -> usize {
    match value {
        Json::Number(digits) => digits.parse().unwrap(),
        other => panic!("not a number: {other:?}"),
    }
}

/// Writes a value with one member or item on each line.
fn pretty(value: &Json, depth: usize, out: &mut String) {
    let pad = |depth: usize, out: &mut String| out.push_str(&"  ".repeat(depth));
    match value {
        Json::Array(items) if !items.is_empty() => {
            out.push_str("[\n");
            for (place, item) in items.iter().enumerate() {
                pad(depth + 1, out);
                pretty(item, depth + 1, out);
                out.push_str(if place + 1 < items.len() { ",\n" } else { "\n" });
            }
            pad(depth, out);
            out.push(']');
        }
        Json::Object(members) if !members.is_empty() => {
            out.push_str("{\n");
            for (place, (name, member)) in members.iter().enumerate() {
                pad(depth + 1, out);
                out.push_str(&String::from_utf8(text(name.clone()).to_bytes()).unwrap());
                out.push_str(": ");
                pretty(member, depth + 1, out);
                out.push_str(if place + 1 < members.len() {
                    ",\n"
                } else {
                    "\n"
                });
            }
            pad(depth, out);
            out.push('}');
        }
        other => out.push_str(&String::from_utf8(other.to_bytes()).unwrap()),
    }
}

fn spec(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("spec")
        .join(file)
}

/// Holds a committed file to what the library makes now, or writes it.
fn check_or_write(path: &Path, value: &Json) {
    let mut made = String::new();
    pretty(value, 0, &mut made);
    made.push('\n');
    if std::env::var_os("SCIONIC_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, &made).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(path)
        .unwrap_or_else(|_| panic!("{} is missing", path.display()))
        .replace("\r\n", "\n");
    assert!(
        committed == made,
        "{} is not what the library makes now. If the format changed on purpose, run the \
         tests once with SCIONIC_WRITE_VECTORS=1 and read what changed.",
        path.display()
    );
}

/// Builds what a vector's description says: a file as parts made from seeds,
/// or a folder of named files and folders.
fn build_node(builder: &mut Builder<'_>, node: &Json) -> Target {
    if node.has("file") {
        let mut content = Vec::new();
        for part in node.get("file").items() {
            content.extend(bytes(
                part.get("seed").text(),
                as_number(part.get("length")),
            ));
        }
        return builder.file_from_bytes(&content).unwrap();
    }
    let mut entries = Vec::new();
    for child in node.get("folder").items() {
        let target = build_node(builder, child);
        let mut extra = ExtraData::new();
        if child.has("extra") {
            for (name, value) in child.get("extra").members() {
                extra.insert(name.clone(), value.text()).unwrap();
            }
        }
        entries.push(Entry::new(child.get("name").text(), target, extra).unwrap());
    }
    builder.folder(entries).unwrap()
}

fn part(seed: &str, length: u64) -> Json {
    object(vec![("seed", text(seed)), ("length", number(length))])
}

fn file(name: &str, parts: Vec<Json>) -> Json {
    object(vec![("name", text(name)), ("file", Json::Array(parts))])
}

fn folder(name: &str, children: Vec<Json>) -> Json {
    object(vec![
        ("name", text(name)),
        ("folder", Json::Array(children)),
    ])
}

fn with_extra(mut entry: Json, name: &str, value: &str) -> Json {
    entry.set("extra", object(vec![(name, text(value))]));
    entry
}

struct Tree {
    store: MemoryStore,
    root: Root,
}

/// Builds one tree, and writes down every byte of it.
fn tree(name: &str, chunking: &str, record_extra: &[(&str, &str)], top: Json) -> (Json, Tree) {
    let store = MemoryStore::new();
    let mut builder = Builder::new(&store, Chunking::from_tag(chunking.as_bytes()).unwrap());
    let target = build_node(&mut builder, &top);
    let mut extra = ExtraData::new();
    for (name, value) in record_extra {
        extra.insert(*name, *value).unwrap();
    }
    let root = builder.finish(target, extra).unwrap();
    let record = record_of(&store, &root).unwrap();
    let totals = record.totals();

    // The tree as one stream gives every list and chunk once, parents first.
    let mut bundle = Vec::new();
    export(&store, &root, &mut bundle).unwrap();
    let (mut lists, mut chunks) = (Vec::new(), Vec::new());
    let mut at = 8;
    while at < bundle.len() {
        let length = u32::from_be_bytes(bundle[at..at + 4].try_into().unwrap()) as usize;
        let frame = &bundle[at + 4..at + 4 + length];
        at += 4 + length;
        let (kind, hash, size) = match frame[0] {
            0x21 => {
                let list = FileList::decode(&frame[1..]).unwrap();
                ("file", *list.hash(), list.size())
            }
            0x22 => {
                let list = FolderList::decode(&frame[1..]).unwrap();
                ("folder", *list.hash(), list.size())
            }
            0x25 => {
                chunks.push(object(vec![
                    ("hash", text(Hash::of(&frame[1..]).to_hex())),
                    ("length", number(frame.len() as u64 - 1)),
                ]));
                continue;
            }
            _ => continue,
        };
        lists.push(object(vec![
            ("kind", text(kind)),
            ("hash", text(hash.to_hex())),
            ("size", number(size)),
            ("bytes", hex(&frame[1..])),
        ]));
    }
    let described = object(vec![
        ("name", text(name)),
        ("chunking", text(chunking)),
        (
            "extra",
            object(
                record_extra
                    .iter()
                    .map(|(name, value)| (*name, text(*value)))
                    .collect(),
            ),
        ),
        ("top", top),
        ("root", text(root.to_text())),
        ("root_hash", text(root.as_hash().to_hex())),
        ("record", hex(&record.encode())),
        ("size", number(record.top().size)),
        ("chunks", number(totals.chunks)),
        ("chunk_bytes", number(totals.chunk_bytes)),
        ("list_bytes", number(totals.list_bytes)),
        ("lists", Json::Array(lists)),
        ("chunk_list", Json::Array(chunks)),
        ("bundle_length", number(bundle.len() as u64)),
        ("bundle_sha256", text(Hash::of(&bundle).to_hex())),
    ]);
    (described, Tree { store, root })
}

fn target_json(target: &Target) -> Json {
    object(vec![
        (
            "kind",
            text(if target.kind == scionic_merkletree::Kind::File {
                "file"
            } else {
                "folder"
            }),
        ),
        ("hash", text(target.hash.to_hex())),
        ("size", number(target.size)),
    ])
}

/// The file or folder at a path of a tree. The empty path is the top.
fn at(tree: &Tree, path: &str) -> Target {
    if path.is_empty() {
        return record_of(&tree.store, &tree.root).unwrap().top();
    }
    lookup(&tree.store, &tree.root, path)
        .unwrap()
        .unwrap()
        .target()
}

fn answer(tree: &Tree, request: &Request) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    Responder::new(&tree.store)
        .answer(&request.encode(), &mut |frame| {
            frames.push(frame.to_vec());
            Ok(())
        })
        .unwrap();
    frames
}

fn extra_raw(values: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = (values.len() as u16).to_be_bytes().to_vec();
    for (name, value) in values {
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

fn entry_raw(kind: u8, size: u64, hash: &Hash, name: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(hash.as_bytes());
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&[0, 0]);
    out
}

fn record_raw(kind: u8, top: &Target, totals: [u64; 3], extra: &[u8]) -> Vec<u8> {
    let mut out = vec![0x20, kind];
    out.extend_from_slice(&top.size.to_be_bytes());
    out.extend_from_slice(top.hash.as_bytes());
    for total in totals {
        out.extend_from_slice(&total.to_be_bytes());
    }
    out.extend_from_slice(extra);
    out
}

/// Forged bytes, each written down only once the library has refused it.
#[derive(Default)]
struct Refused(Vec<Json>);

impl Refused {
    fn add(
        &mut self,
        kind: &str,
        what: &str,
        bytes: &[u8],
        more: Vec<(&str, Json)>,
        refused: bool,
    ) {
        assert!(refused, "the library takes {kind}: {what}");
        let mut members = vec![
            ("as", text(kind)),
            ("what", text(what)),
            ("bytes", hex(bytes)),
        ];
        members.extend(more);
        self.0.push(object(members));
    }

    fn record(&mut self, what: &str, bytes: &[u8]) {
        self.add(
            "record",
            what,
            bytes,
            Vec::new(),
            Record::decode(bytes).is_err(),
        );
    }

    fn file_list(&mut self, what: &str, bytes: &[u8]) {
        let refused = FileList::decode(bytes).is_err();
        self.add("file-list", what, bytes, Vec::new(), refused);
    }

    /// A file's list that is well formed, and does not fit a way of chunking.
    fn file_list_chunking(&mut self, what: &str, chunking: &str, bytes: &[u8]) {
        let list = FileList::decode(bytes).unwrap();
        let refused = list
            .check_chunking(Chunking::from_tag(chunking.as_bytes()).unwrap())
            .is_err();
        let more = vec![("chunking", text(chunking))];
        self.add("file-list-chunking", what, bytes, more, refused);
    }

    fn folder_list(&mut self, what: &str, bytes: &[u8]) {
        let refused = FolderList::decode(bytes).is_err();
        self.add("folder-list", what, bytes, Vec::new(), refused);
    }

    fn file_branch(&mut self, what: &str, against: &Target, bytes: &[u8]) {
        let refused = FileBranch::decode(bytes)
            .and_then(|branch| branch.check(against, None))
            .is_err();
        let more = vec![("against", target_json(against))];
        self.add("file-branch", what, bytes, more, refused);
    }

    fn folder_branch(&mut self, what: &str, against: &Target, bytes: &[u8]) {
        let refused = FolderBranch::decode(bytes)
            .and_then(|branch| branch.check(against))
            .is_err();
        let more = vec![("against", target_json(against))];
        self.add("folder-branch", what, bytes, more, refused);
    }

    fn folder_name(&mut self, what: &str, against: &Target, name: &str, bytes: &[u8]) {
        let refused = FolderBranch::decode(bytes)
            .and_then(|branch| branch.check_name(against, name).map(|_| ()))
            .is_err();
        let more = vec![("against", target_json(against)), ("name", text(name))];
        self.add("folder-name", what, bytes, more, refused);
    }

    fn request(&mut self, what: &str, bytes: &[u8]) {
        let refused = Request::decode(bytes).is_err();
        self.add("request", what, bytes, Vec::new(), refused);
    }

    fn frame(&mut self, what: &str, bytes: &[u8]) {
        self.add(
            "frame",
            what,
            bytes,
            Vec::new(),
            Frame::decode(bytes).is_err(),
        );
    }

    fn root(&mut self, what: &str, spelled: &str) {
        assert!(
            Root::parse(spelled).is_err(),
            "the library reads a root: {what}"
        );
        self.0.push(object(vec![
            ("as", text("root")),
            ("what", text(what)),
            ("text", text(spelled)),
        ]));
    }
}

fn sample_top() -> Json {
    object(vec![(
        "folder",
        Json::Array(vec![
            folder(
                "data",
                vec![file("exactly-two-chunks.bin", vec![part("two", 32)])],
            ),
            file("empty.bin", Vec::new()),
            folder("nothing-here", Vec::new()),
            with_extra(
                file("readme.txt", vec![part("readme", 12)]),
                "type",
                "text/plain",
            ),
            with_extra(
                folder(
                    "weights",
                    vec![
                        file("copy-of-model.bin", vec![part("model", 1_000)]),
                        file("model.bin", vec![part("model", 1_000)]),
                        folder(
                            "shards",
                            vec![
                                file("a.bin", vec![part("shard-a", 100)]),
                                file("b.bin", vec![part("shard-b", 33)]),
                            ],
                        ),
                    ],
                ),
                "note",
                "the weights",
            ),
        ]),
    )])
}

fn manifest() -> Json {
    let top_file = |parts: Vec<Json>| object(vec![("file", Json::Array(parts))]);
    let (mut trees, mut built) = (Vec::new(), Vec::new());
    for (name, chunking, extra, top) in [
        ("empty-file", "fixed-16", vec![], top_file(Vec::new())),
        (
            "one-chunk",
            "fixed-16",
            vec![],
            top_file(vec![part("one", 5)]),
        ),
        (
            "three-chunks",
            "fixed-16",
            vec![],
            top_file(vec![part("three", 40)]),
        ),
        (
            "a-chunk-twice",
            "fixed-16",
            vec![],
            top_file(vec![part("x", 16), part("y", 16), part("x", 16)]),
        ),
        (
            "empty-folder",
            "fixed-16",
            vec![],
            object(vec![("folder", Json::Array(Vec::new()))]),
        ),
        (
            "folder",
            "fixed-16",
            vec![("name", "a sample")],
            sample_top(),
        ),
        (
            "chunked-by-content",
            "fastcdc-v1",
            vec![],
            top_file(vec![part("scionic-fastcdc-v1:corpus:random_3mib", 3 << 20)]),
        ),
    ] {
        let (described, tree) = tree(name, chunking, &extra, top);
        trees.push(described);
        built.push(tree);
    }
    let sample = &built[5];
    let top = at(sample, "");
    let weights = at(sample, "weights");
    let model = at(sample, "weights/model.bin");
    let shard_b = at(sample, "weights/shards/b.bin");
    let model_list = file_of(&sample.store, &model).unwrap();
    let top_list = folder_of(&sample.store, &top).unwrap();

    // Parts of the sample folder, as they are shown.
    let mut branches = Vec::new();
    for (start, end) in [(0, 1), (0, 63), (62, 63), (6, 28), (31, 33)] {
        let branch = model_list.open(start, end).unwrap();
        branches.push(object(vec![
            ("tree", text("folder")),
            ("path", text("weights/model.bin")),
            ("of", target_json(&model)),
            ("start", number(start)),
            ("end", number(end)),
            (
                "starts_at_byte",
                number(branch.check(&model, None).unwrap()),
            ),
            ("frame", hex(&file_branch_frame(&branch))),
        ]));
    }
    for (path, start, end) in [("", 0, 5), ("", 2, 3), ("", 4, 5), ("weights", 0, 2)] {
        let of = at(sample, path);
        let branch = folder_of(&sample.store, &of)
            .unwrap()
            .open(start, end)
            .unwrap();
        branch.check(&of).unwrap();
        branches.push(object(vec![
            ("tree", text("folder")),
            ("path", text(path)),
            ("of", target_json(&of)),
            ("start", number(start)),
            ("end", number(end)),
            ("frame", hex(&folder_branch_frame(&branch))),
        ]));
    }

    // One name of a folder: there, and not there.
    let mut names = Vec::new();
    for (path, name) in [
        ("", "readme.txt"),
        ("", "weights"),
        ("", "a"),
        ("", "readme.txs"),
        ("", "zzz"),
        ("weights", "model.bin"),
        ("weights", "absent"),
        ("nothing-here", "anything"),
    ] {
        let of = at(sample, path);
        let branch = folder_of(&sample.store, &of)
            .unwrap()
            .open_name(name)
            .unwrap();
        let found = branch.check_name(&of, name).unwrap().is_some();
        names.push(object(vec![
            ("tree", text("folder")),
            ("path", text(path)),
            ("of", target_json(&of)),
            ("name", text(name)),
            ("found", Json::Bool(found)),
            ("frame", hex(&folder_branch_frame(&branch))),
        ]));
    }

    // Every kind of request, and what the sample's holder answers.
    let unknown = Hash::of(b"nobody holds this");
    let readme_chunk = file_of(&sample.store, &at(sample, "readme.txt"))
        .unwrap()
        .items()[0]
        .hash;
    let asked: Vec<(&str, Request)> = vec![
        ("the record", Request::Record(sample.root)),
        ("the top folder's list", Request::Folder(top.hash)),
        (
            "two entries of weights, from the second",
            Request::FolderBranch {
                folder: weights.hash,
                start: 1,
                count: 2,
            },
        ),
        (
            "one name of the top folder",
            Request::FolderName {
                folder: top.hash,
                name: "readme.txt".to_owned(),
            },
        ),
        ("a file's list", Request::File(shard_b.hash)),
        (
            "four items of a file's list, from the fourth",
            Request::FileBranch {
                file: model.hash,
                start: 3,
                count: 4,
            },
        ),
        (
            "the branch that holds 40 bytes of a file, from byte 100",
            Request::FileBytes {
                file: model.hash,
                offset: 100,
                length: 40,
            },
        ),
        (
            "ten chunks of a file that has three",
            Request::Chunks {
                file: shard_b.hash,
                start: 0,
                count: 10,
            },
        ),
        ("one chunk", Request::Chunk(readme_chunk)),
        ("which chunks of a file are held", Request::Have(model.hash)),
        ("a file that is not held", Request::File(unknown)),
        (
            "chunks beyond a file's last",
            Request::Chunks {
                file: shard_b.hash,
                start: 3,
                count: 1,
            },
        ),
    ];
    let mut answers = Vec::new();
    for (what, request) in &asked {
        let frames = answer(sample, request);
        answers.push(object(vec![
            ("tree", text("folder")),
            ("what", text(*what)),
            ("request", hex(&request.encode())),
            (
                "frames",
                Json::Array(frames.iter().map(|frame| hex(frame)).collect()),
            ),
        ]));
    }
    // The same on a connection: the first, the eighth and the eleventh.
    let mut sent = Vec::new();
    for place in [0, 7, 10] {
        let request = asked[place].1.encode();
        sent.extend_from_slice(&(request.len() as u32).to_be_bytes());
        sent.extend_from_slice(&request);
    }
    let mut received = Vec::new();
    serve(&sample.store, &mut sent.as_slice(), &mut received).unwrap();
    let connection = object(vec![
        ("tree", text("folder")),
        ("sent", hex(&sent)),
        ("received", hex(&received)),
    ]);

    // What must be refused.
    let mut refused = Refused::default();
    let record = record_of(&sample.store, &sample.root).unwrap();
    let honest = record.encode();
    let totals = record.totals();
    let right = [totals.chunks, totals.chunk_bytes, totals.list_bytes];
    let chunking = extra_raw(&[(b"chunking", b"fixed-16")]);
    let mut changed = honest.clone();
    changed[0] = 0x21;
    refused.record("another first byte", &changed);
    refused.record("a byte after its end", &[honest.clone(), vec![0]].concat());
    refused.record("cut short by a byte", &honest[..honest.len() - 1]);
    refused.record(
        "it does not say how the tree was chunked",
        &record_raw(2, &top, right, &extra_raw(&[])),
    );
    for tag in [
        "fastcdc-v2",
        "fixed-016",
        "fixed-0",
        "fixed-8388609",
        "fixed-",
        "",
    ] {
        refused.record(
            &format!("a way of chunking that is not known: {tag:?}"),
            &record_raw(2, &top, right, &extra_raw(&[(b"chunking", tag.as_bytes())])),
        );
    }
    refused.record(
        "a kind that is neither a file nor a folder",
        &record_raw(3, &top, right, &chunking),
    );
    refused.record(
        "more chunks than chunk bytes",
        &record_raw(2, &top, [right[1] + 1, right[1], right[2] * 40], &chunking),
    );
    refused.record(
        "more chunk bytes than the tree's size",
        &record_raw(2, &top, [right[0], top.size + 1, right[2]], &chunking),
    );
    refused.record(
        "fewer list bytes than 36 a chunk",
        &record_raw(2, &top, [right[0], right[1], right[0] * 36 - 1], &chunking),
    );
    refused.record(
        "extra values out of order",
        &record_raw(
            2,
            &top,
            right,
            &extra_raw(&[(b"name", b"x"), (b"chunking", b"fixed-16")]),
        ),
    );
    refused.record(
        "an extra value's name twice",
        &record_raw(
            2,
            &top,
            right,
            &extra_raw(&[(b"chunking", b"fixed-16"), (b"chunking", b"fixed-16")]),
        ),
    );
    refused.record(
        "an extra value with no name",
        &record_raw(
            2,
            &top,
            right,
            &extra_raw(&[(b"", b"x"), (b"chunking", b"fixed-16")]),
        ),
    );

    let item = |seed: &str, length: u32| {
        let mut bytes = Hash::of(seed.as_bytes()).as_bytes().to_vec();
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes
    };
    refused.file_list("35 bytes", &item("a", 16)[..35]);
    refused.file_list("a chunk of no bytes", &item("a", 0));
    refused.file_list("a chunk of more than 8 MiB", &item("a", (8 << 20) + 1));
    refused.file_list_chunking(
        "a chunk in the middle that is shorter than the tree's chunks",
        "fixed-16",
        &[item("a", 16), item("b", 9), item("c", 16)].concat(),
    );
    refused.file_list_chunking(
        "a last chunk that is longer than the tree's chunks",
        "fixed-16",
        &[item("a", 16), item("b", 17)].concat(),
    );
    refused.file_list_chunking(
        "a chunk that is not the last and holds exactly 512 KiB",
        "fastcdc-v1",
        &[item("a", 512 << 10), item("b", 1)].concat(),
    );
    refused.file_list_chunking(
        "small chunks in a tree that is chunked by content",
        "fastcdc-v1",
        &[item("a", 16), item("b", 16)].concat(),
    );

    let some = Hash::of(b"some file");
    let entries = |names: &[&[u8]]| -> Vec<u8> {
        names
            .iter()
            .flat_map(|name| entry_raw(1, 1, &some, name))
            .collect()
    };
    FolderList::decode(&entries(&[b"a", b"b"])).unwrap();
    refused.folder_list("two names out of order", &entries(&[b"b", b"a"]));
    refused.folder_list("one name twice", &entries(&[b"a", b"a"]));
    refused.folder_list("a name with a slash", &entries(&[b"a/b"]));
    refused.folder_list("the name of one dot", &entries(&[b"."]));
    refused.folder_list("the name of two dots", &entries(&[b".."]));
    refused.folder_list("an empty name", &entries(&[b""]));
    refused.folder_list("a name with a zero byte", &entries(&[b"a\0b"]));
    refused.folder_list("a name that is not UTF-8", &entries(&[b"a\xffb"]));
    refused.folder_list("a name of 256 bytes", &entries(&[&[b'a'; 256]]));
    refused.folder_list(
        "a kind that is neither a file nor a folder",
        &entry_raw(0, 1, &some, b"a"),
    );
    let whole = entries(&[b"a", b"b"]);
    refused.folder_list("cut short by a byte", &whole[..whole.len() - 1]);

    let branch = model_list.open(6, 9).unwrap().encode();
    assert_eq!(
        FileBranch::decode(&branch)
            .unwrap()
            .check(&model, None)
            .unwrap(),
        96
    );
    let with = |at: usize, by: u8| {
        let mut forged = branch.clone();
        forged[at] = forged[at].wrapping_add(by);
        forged
    };
    refused.file_branch("under a count that is one more", &model, &with(7, 1));
    refused.file_branch("at a place that is one further", &model, &with(15, 1));
    refused.file_branch("an item with another length", &model, &with(20 + 35, 1));
    refused.file_branch("an item with another hash", &model, &with(20, 1));
    refused.file_branch(
        "a carried node with another size",
        &model,
        &with(branch.len() - 1, 1),
    );
    let carried_at = 20 + 3 * 36;
    let carried = u16::from_be_bytes([branch[carried_at], branch[carried_at + 1]]);
    let recount = |count: u16, bytes: &[u8]| {
        let mut forged = bytes.to_vec();
        forged[carried_at..carried_at + 2].copy_from_slice(&count.to_be_bytes());
        forged
    };
    refused.file_branch(
        "a carried node left out",
        &model,
        &recount(carried - 1, &branch[..branch.len() - 40]),
    );
    refused.file_branch(
        "a carried node too many",
        &model,
        &recount(
            carried + 1,
            &[&branch[..], &branch[branch.len() - 40..]].concat(),
        ),
    );
    let mut nothing = branch[..16].to_vec();
    nothing.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    refused.file_branch("a branch that shows nothing", &model, &nothing);
    refused.file_branch("a branch of another file", &shard_b, &branch);
    refused.file_branch("a file's branch held against a folder", &weights, &branch);

    let shown = top_list.open(2, 3).unwrap().encode();
    FolderBranch::decode(&shown).unwrap().check(&top).unwrap();
    let mut other_kind = shown.clone();
    other_kind[20] = 1;
    refused.folder_branch("a folder shown as a file", &top, &other_kind);
    let mut other_name = shown.clone();
    other_name[20 + 43] ^= 1;
    refused.folder_branch("an entry with another name", &top, &other_name);
    refused.folder_branch("a branch of another folder", &weights, &shown);
    refused.folder_branch(
        "an empty folder's branch for a folder that has entries",
        &top,
        &[0; 22],
    );
    // A fork hashes the first name of its right half. The carried node that
    // begins the list is in no right half: it comes with no name, and every
    // other carried node comes with one.
    let first_name_at = 20 + top_list.entries()[2].encoded_len() + 2 + 40;
    assert_eq!(shown[first_name_at..first_name_at + 2], [0, 0]);
    let mut named = shown.clone();
    named.splice(first_name_at..first_name_at + 2, [0, 1, b'a']);
    refused.folder_branch(
        "a name for the carried node that begins the list",
        &top,
        &named,
    );
    let from_the_start = top_list.open(0, 1).unwrap().encode();
    FolderBranch::decode(&from_the_start)
        .unwrap()
        .check(&top)
        .unwrap();
    let name_at = 20 + top_list.entries()[0].encoded_len() + 2 + 40;
    let name_len = usize::from(u16::from_be_bytes([
        from_the_start[name_at],
        from_the_start[name_at + 1],
    ]));
    assert!(name_len > 0);
    let mut nameless = from_the_start.clone();
    nameless.splice(name_at..name_at + 2 + name_len, [0, 0]);
    refused.folder_branch(
        "no name for a carried node that is not the one that begins the list",
        &top,
        &nameless,
    );
    let for_readme = top_list.open_name("readme.txt").unwrap().encode();
    refused.folder_name(
        "the entry of one name as the answer for another",
        &top,
        "weights",
        &for_readme,
    );
    refused.folder_name(
        "an entry that is not where a search for the name ends",
        &top,
        "zzz",
        &for_readme,
    );
    refused.folder_name(
        "two entries as the answer for one name",
        &top,
        "readme.txt",
        &{ top_list.open(3, 5).unwrap().encode() },
    );

    let ask = Request::Record(sample.root).encode();
    refused.request("no bytes", &[]);
    refused.request(
        "a first byte that asks for nothing",
        &[&[0x3a][..], &ask[1..]].concat(),
    );
    refused.request("cut short by a byte", &ask[..ask.len() - 1]);
    refused.request("a byte after its end", &[ask.clone(), vec![0]].concat());
    let mut named = vec![0x33];
    named.extend_from_slice(top.hash.as_bytes());
    refused.request(
        "a name with a slash",
        &[&named[..], &[0, 3], b"a/b"].concat(),
    );
    refused.request(
        "a name shorter than its length says",
        &[&named[..], &[0, 4], b"abc"].concat(),
    );
    refused.request("an empty name", &[&named[..], &[0, 0]].concat());

    let have = answer(sample, &Request::Have(model.hash)).remove(0);
    let mut spare = have.clone();
    *spare.last_mut().unwrap() |= 1;
    refused.frame("no bytes", &[]);
    refused.frame("a first byte that is no frame's", &[0x28, 0]);
    refused.frame("a spare bit set in what a peer holds", &spare);
    refused.frame(
        "fewer bytes than what a peer holds needs",
        &have[..have.len() - 1],
    );
    refused.frame("a refusal that says nothing", &[0x27]);
    refused.frame("a refusal for no reason that there is", &[0x27, 0]);
    refused.frame("a refusal for a reason that there is not", &[0x27, 3]);
    refused.frame("a chunk of no bytes", &[0x25]);

    let spelled = sample.root.to_text();
    refused.root("in capital letters", &spelled.to_uppercase());
    refused.root("a letter short", &spelled[..spelled.len() - 1]);
    refused.root("a letter more", &format!("{spelled}a"));
    refused.root("another first letter", &format!("z{}", &spelled[1..]));
    refused.root("the hash as hex", &sample.root.as_hash().to_hex());
    refused.root(
        "a CID of another kind of content",
        &spelled.replacen("bafkrei", "bafybei", 1),
    );
    refused.root("nothing", "");

    object(vec![
        ("format", text("scionic-vectors-1")),
        (
            "bytes",
            text(
                "A part of a file is made from its seed: block k is SHA-256(seed + k), with k \
                 as 8 bytes, big-endian, from 0. The blocks are joined and cut to the length. \
                 A file is its parts joined.",
            ),
        ),
        ("trees", Json::Array(trees)),
        ("branches", Json::Array(branches)),
        ("names", Json::Array(names)),
        ("answers", Json::Array(answers)),
        ("connection", connection),
        ("refused", Json::Array(refused.0)),
    ])
}

#[test]
fn the_shared_vectors_are_what_the_library_makes() {
    check_or_write(&spec("vectors/manifest.json"), &manifest());
}

/// The chunking vectors also say what each file hashes to. That follows from
/// its chunks' hashes and lengths alone, so it is worked out from them here.
/// `tests/fastcdc_vectors.rs` chunks the real bytes and holds them to it.
#[test]
fn the_chunking_vectors_say_what_each_file_hashes_to() {
    let path = spec("fastcdc-vectors/manifest.json");
    let mut manifest = Json::parse(&std::fs::read(&path).unwrap());
    let mut cases = Vec::new();
    for case in manifest.get("cases").items() {
        let mut start = 0;
        let mut items = Vec::new();
        for (end, hash) in case
            .get("boundaries")
            .items()
            .iter()
            .zip(case.get("chunk_sha256").items())
        {
            let end = as_number(end);
            items.push(ChunkRef {
                hash: Hash::from_hex(hash.text()).unwrap(),
                length: (end - start) as u32,
            });
            start = end;
        }
        let list = FileList::new(items).unwrap();
        list.check_chunking(Chunking::FastCdcV1).unwrap();
        let mut kept = Vec::new();
        for (name, value) in case.members() {
            // What the layout before this one said of a case is left out.
            if !["root_hash", "leaf_count", "chunk_leaves", "file_hash"].contains(&name.as_str()) {
                kept.push((name.as_str(), value.clone()));
            }
        }
        kept.push(("file_hash", text(list.hash().to_hex())));
        cases.push(object(kept));
    }
    manifest.set("cases", Json::Array(cases));
    check_or_write(&path, &manifest);
}
