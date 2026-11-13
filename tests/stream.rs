//! Syncing over a connection: requests one way, answers the other.

mod support;

use scionic_merkletree::{
    fetch, lookup, record_of, serve, verify, Builder, Entry, Error, ExtraData, MemoryStore, Peer,
    Remote, Request, Result, Root, StreamPeer, MAX_RECORD_BYTES, MAX_REQUEST_BYTES,
    REQUESTS_AHEAD_BYTES,
};
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use support::{bytes, contents, pipe, sample_tree, small_pieces, PipeReader, PipeWriter};

/// Counts what a client sends between one flush and the next.
struct Flights<W> {
    inner: W,
    current: usize,
    sizes: Arc<Mutex<Vec<usize>>>,
}

impl<W: Write> Write for Flights<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(bytes)?;
        self.current += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sizes.lock().unwrap().push(self.current);
        self.current = 0;
        self.inner.flush()
    }
}

type Client = StreamPeer<PipeReader, Flights<PipeWriter>>;

/// Serves `source` on one thread, and runs `client` on this one, with a
/// connection between them that holds no more than it is given: so many
/// bytes on the way to the server, and so many on the way back.
///
/// Gives what the client gave, how the serving ended, and how many bytes
/// the client sent between one flush and the next.
fn connected<T>(
    source: &MemoryStore,
    to_server: usize,
    to_client: usize,
    client: impl FnOnce(&mut Client) -> T,
) -> (T, Result<()>, Vec<usize>) {
    let (mut server_in, client_out) = pipe(to_server);
    let (client_in, mut server_out) = pipe(to_client);
    let sizes = Arc::new(Mutex::new(Vec::new()));
    let client_out = Flights {
        inner: client_out,
        current: 0,
        sizes: Arc::clone(&sizes),
    };
    let (result, served) = std::thread::scope(|scope| {
        let server = scope.spawn(move || serve(source, &mut server_in, &mut server_out));
        let mut peer = StreamPeer::new(client_in, client_out);
        let result = client(&mut peer);
        // The client hangs up, and the serving ends.
        drop(peer);
        (result, server.join().unwrap())
    });
    let sizes = sizes.lock().unwrap().clone();
    (result, served, sizes)
}

#[test]
fn a_tree_is_fetched_over_a_connection() {
    let (_temp, source, root) = sample_tree("stream-fetch");
    // A connection that holds next to nothing on the way back, so that the
    // server waits on every answer until the client reads it, and one with
    // room to spare.
    for (to_server, to_client) in [
        (REQUESTS_AHEAD_BYTES, 1),
        (REQUESTS_AHEAD_BYTES, 100),
        (1 << 20, 1 << 20),
    ] {
        let dest = MemoryStore::new();
        let (summary, served, _) = connected(&source, to_server, to_client, |peer| {
            fetch(&dest, &root, peer)
        });
        served.unwrap();
        assert_eq!(summary.unwrap(), verify(&dest, &root).unwrap());
        assert_eq!(contents(&dest), contents(&source));
    }
}

#[test]
fn parts_of_a_tree_are_read_over_a_connection() {
    let (_temp, source, root) = sample_tree("stream-parts");
    let content = bytes("model", 1_000);
    let ((), served, _) = connected(&source, REQUESTS_AHEAD_BYTES, 7, |peer| {
        let mut remote = Remote::open(peer, &root).unwrap();
        assert_eq!(remote.record(), &record_of(&source, &root).unwrap());
        let model = remote.lookup("weights/model.bin").unwrap().unwrap();
        assert_eq!(
            Some(&model),
            lookup(&source, &root, "weights/model.bin")
                .unwrap()
                .as_ref()
        );
        assert!(remote.lookup("weights/absent").unwrap().is_none());
        let mut out = Vec::new();
        remote.read(&model.target(), 100, 333, &mut out).unwrap();
        assert_eq!(out, &content[100..433]);
        assert_eq!(remote.have(&model.target()).unwrap().held(), 63);
        let weights = remote.lookup("weights").unwrap().unwrap();
        assert_eq!(remote.entries(&weights.target(), 0, 10).unwrap().total, 3);
    });
    served.unwrap();
}

#[test]
fn requests_are_sent_ahead_of_their_answers_and_never_too_far() {
    // A folder of 150 small files: more lists than one round asks for, and
    // more requests in a round than are sent ahead at once.
    let source = MemoryStore::new();
    let mut builder = Builder::new(&source, small_pieces());
    let entries: Vec<Entry> = (0..150)
        .map(|index| {
            let file = builder
                .file_from_bytes(&bytes(&format!("file-{index}"), 20))
                .unwrap();
            Entry::new(format!("f{index:03}"), file, ExtraData::new()).unwrap()
        })
        .collect();
    let top = builder.folder(entries).unwrap();
    let root = builder.finish(top, ExtraData::new()).unwrap();

    // The connection holds on the way to the server exactly what a client
    // may send ahead, and on the way back one byte. A client that sent
    // further ahead would wait for the server, which waits for the client.
    let dest = MemoryStore::new();
    let (summary, served, flights) = connected(&source, REQUESTS_AHEAD_BYTES, 1, |peer| {
        fetch(&dest, &root, peer)
    });
    served.unwrap();
    summary.unwrap();
    assert_eq!(contents(&dest), contents(&source));

    // 1 record, 1 folder, 150 lists and 150 requests for pieces.
    let sent: usize = flights.iter().sum();
    assert_eq!(sent, (33 + 4) * 152 + (45 + 4) * 150);
    assert!(flights.iter().all(|flight| *flight <= REQUESTS_AHEAD_BYTES));
    // 64 requests for lists take 2,368 bytes, so a round goes out in two
    // flights, and the first holds as many requests as fit.
    assert!(flights.contains(&(55 * 37)), "{flights:?}");
    assert!(flights.len() < 30, "{flights:?}");
}

/// Serves requests that are all there already, and gives what was answered.
fn served(source: &MemoryStore, requests: &[u8]) -> (Result<()>, Vec<u8>) {
    let mut answers = Vec::new();
    let result = serve(source, &mut &requests[..], &mut answers);
    (result, answers)
}

fn framed(bytes: &[u8]) -> Vec<u8> {
    [&(bytes.len() as u32).to_be_bytes()[..], bytes].concat()
}

#[test]
fn an_answer_is_its_frames_and_then_a_length_of_zero() {
    let (_temp, source, root) = sample_tree("stream-bytes");
    let record = record_of(&source, &root).unwrap().encode();
    let unknown = Root::of_record(b"nobody holds this");

    // Nothing asked, nothing answered.
    let (result, answers) = served(&source, &[]);
    result.unwrap();
    assert!(answers.is_empty());

    // Two requests: one for a record that is held, and one for a record that
    // is not.
    let requests = [
        framed(&Request::Record(root).encode()),
        framed(&Request::Record(unknown).encode()),
    ]
    .concat();
    let (result, answers) = served(&source, &requests);
    result.unwrap();
    let expected = [
        framed(&record),
        vec![0, 0, 0, 0],
        framed(&[0x27, 1]),
        vec![0, 0, 0, 0],
    ]
    .concat();
    assert_eq!(answers, expected);

    // A request that is malformed ends the serving, and so does one that is
    // empty, one that is too long, and one that the stream ends inside.
    let too_long = vec![0x33; MAX_REQUEST_BYTES + 1];
    for bad in [
        framed(&[0x3a, 1, 2]),
        framed(&[0x30; 32]),
        framed(&[]),
        framed(&too_long),
        framed(&Request::Record(root).encode())[..20].to_vec(),
    ] {
        let (result, answers) = served(&source, &bad);
        assert!(result.is_err(), "{bad:?}");
        assert!(answers.is_empty());
    }
    // What came before it is answered.
    let requests = [framed(&Request::Record(root).encode()), framed(&[0x3a])].concat();
    let (result, answers) = served(&source, &requests);
    assert!(matches!(result, Err(Error::InvalidData { .. })));
    assert_eq!(answers, [framed(&record), vec![0, 0, 0, 0]].concat());
}

#[test]
fn a_connection_that_an_answer_left_half_read_is_not_used_again() {
    let (_temp, source, root) = sample_tree("stream-broken");
    let request = Request::Record(root).encode();

    // An answer that is longer than its asker takes is refused by its
    // length. Its bytes are still on the connection, unread.
    let (results, _, _) = connected(&source, 4096, 4096, |peer| {
        let first = peer.ask(&request, 10, &mut |_| Ok(()));
        let second = peer.ask(&request, MAX_RECORD_BYTES, &mut |_| Ok(()));
        (first, second)
    });
    assert!(matches!(results.0, Err(Error::LimitExceeded { .. })));
    assert!(matches!(results.1, Err(Error::Peer { .. })));

    // The same when the asker refuses a frame for what is in it.
    let (results, _, _) = connected(&source, 4096, 4096, |peer| {
        let first = peer.ask(&request, MAX_RECORD_BYTES, &mut |_| {
            Err(Error::IntakeFailed)
        });
        let second = peer.ask(&request, MAX_RECORD_BYTES, &mut |_| Ok(()));
        (first, second)
    });
    assert!(matches!(results.0, Err(Error::IntakeFailed)));
    assert!(matches!(results.1, Err(Error::Peer { .. })));

    // A connection whose answers were all read to their end is used again.
    let (frames, served, _) = connected(&source, 4096, 4096, |peer| {
        let mut frames = 0;
        for _ in 0..3 {
            peer.ask(&request, MAX_RECORD_BYTES, &mut |_| {
                frames += 1;
                Ok(())
            })
            .unwrap();
        }
        frames
    });
    served.unwrap();
    assert_eq!(frames, 3);
}
