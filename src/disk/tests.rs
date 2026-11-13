use super::{Found, Held, Refused};
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// A new, empty place among the system's passing files, removed at the end.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "scionic-disk-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn kinds(held: &Held) -> Vec<(String, Found)> {
    let mut listed: Vec<(String, Found)> = held
        .list()
        .unwrap()
        .into_iter()
        .map(|(name, found)| (name.into_string().unwrap(), found))
        .collect();
    listed.sort_by(|left, right| left.0.cmp(&right.0));
    listed
}

fn read(file: Result<fs::File, Refused>) -> String {
    let mut text = String::new();
    match file {
        Ok(mut file) => file.read_to_string(&mut text).unwrap(),
        Err(refused) => panic!("not opened: {refused:?}"),
    };
    text
}

#[test]
fn what_is_in_a_held_folder_is_made_listed_and_opened() {
    let scratch = Scratch::new("made");
    let top = Held::create(&scratch.0.join("top")).unwrap();
    assert!(
        Held::create(&scratch.0.join("top")).is_err(),
        "a taken place"
    );
    assert_eq!(top.path(), scratch.0.join("top"));
    let inner = top.create_folder("inner").unwrap();
    top.create_file("file")
        .unwrap()
        .write_all(b"bytes")
        .unwrap();
    inner
        .create_file("deep")
        .unwrap()
        .write_all(b"deeper")
        .unwrap();
    // Nothing is made where something is.
    assert!(top.create_file("file").is_err());
    assert!(top.create_file("inner").is_err());
    assert!(top.create_folder("inner").is_err());
    assert!(top.create_folder("file").is_err());
    assert_eq!(
        kinds(&top),
        [
            ("file".to_owned(), Found::File),
            ("inner".to_owned(), Found::Folder)
        ]
    );
    assert_eq!(read(top.open_file("file")), "bytes");
    let again = Held::open(&scratch.0.join("top")).unwrap();
    let again = again.open_folder("inner").map_err(|_| ()).unwrap();
    assert_eq!(read(again.open_file("deep")), "deeper");
    // One kind of thing is not opened as the other.
    assert!(matches!(top.open_file("inner"), Err(Refused::Other)));
    assert!(matches!(top.open_folder("file"), Err(Refused::Other)));
    assert!(matches!(top.open_file("absent"), Err(Refused::Io(_))));
    assert!(matches!(top.open_folder("absent"), Err(Refused::Io(_))));
}

#[cfg(unix)]
#[test]
fn a_link_is_refused_wherever_it_stands() {
    use std::os::unix::fs::symlink;
    let scratch = Scratch::new("links");
    let root = &scratch.0;
    fs::create_dir_all(root.join("secret")).unwrap();
    fs::write(root.join("secret/key"), b"secret").unwrap();
    fs::create_dir_all(root.join("top/real")).unwrap();
    fs::write(root.join("top/real/file"), b"mine").unwrap();
    symlink(root.join("secret"), root.join("top/to-folder")).unwrap();
    symlink(root.join("secret/key"), root.join("top/to-file")).unwrap();
    symlink(root.join("nowhere"), root.join("top/to-nothing")).unwrap();
    let top = Held::open(&root.join("top")).unwrap();
    assert_eq!(
        kinds(&top),
        [
            ("real".to_owned(), Found::Folder),
            ("to-file".to_owned(), Found::Link),
            ("to-folder".to_owned(), Found::Link),
            ("to-nothing".to_owned(), Found::Link),
        ]
    );
    assert!(matches!(top.open_folder("to-folder"), Err(Refused::Link)));
    assert!(matches!(top.open_file("to-file"), Err(Refused::Link)));
    assert!(matches!(top.open_file("to-folder"), Err(Refused::Link)));
    assert!(matches!(top.open_file("to-nothing"), Err(Refused::Link)));
    // Nothing is made through a link, or in the place of one.
    assert!(top.create_file("to-nothing").is_err());
    assert!(top.create_folder("to-nothing").is_err());
    assert!(top.create_file("to-folder").is_err());
    assert!(!root.join("nowhere").exists());

    // A folder that is held stays the folder it was, whatever becomes of
    // its name: here the name is given to a link that leads elsewhere.
    let real = top.open_folder("real").map_err(|_| ()).unwrap();
    fs::rename(root.join("top/real"), root.join("top/moved")).unwrap();
    symlink(root.join("secret"), root.join("top/real")).unwrap();
    fs::write(root.join("secret/file"), b"not mine").unwrap();
    assert_eq!(read(real.open_file("file")), "mine");
    assert!(matches!(top.open_folder("real"), Err(Refused::Link)));
    // What is made in it lands in it, and not where the link leads.
    real.create_file("new").unwrap();
    assert!(root.join("top/moved/new").exists());
    assert!(!root.join("secret/new").exists());

    // The place a caller names is the caller's, link or not.
    symlink(root.join("top"), root.join("alias")).unwrap();
    let alias = Held::open(&root.join("alias")).unwrap();
    assert!(alias.open_folder("moved").is_ok());

    // A pipe that took a file's place is refused, and not waited on.
    let pipe = root.join("top/pipe");
    let made = std::process::Command::new("mkfifo").arg(&pipe).status();
    if made.is_ok_and(|status| status.success()) {
        assert!(matches!(top.open_file("pipe"), Err(Refused::Other)));
    }
}

#[cfg(windows)]
#[test]
fn a_folder_that_is_held_can_be_neither_renamed_nor_replaced() {
    let scratch = Scratch::new("pinned");
    let root = &scratch.0;
    fs::create_dir_all(root.join("top/a/b")).unwrap();
    fs::create_dir_all(root.join("top/a/empty")).unwrap();
    fs::write(root.join("top/a/b/file"), b"mine").unwrap();
    let top = Held::open(&root.join("top")).unwrap();
    let a = top.open_folder("a").map_err(|_| ()).unwrap();
    let b = a.open_folder("b").map_err(|_| ()).unwrap();
    let empty = a.open_folder("empty").map_err(|_| ()).unwrap();
    // The lower folders keep the ones above them held.
    drop(a);
    drop(top);
    assert!(fs::rename(root.join("top/a/b"), root.join("top/a/c")).is_err());
    assert!(fs::rename(root.join("top/a"), root.join("top/z")).is_err());
    assert!(fs::rename(root.join("top"), root.join("gone")).is_err());
    assert!(fs::remove_dir(root.join("top/a/empty")).is_err());
    assert_eq!(read(b.open_file("file")), "mine");
    // Let go of, they are anyone's again.
    drop(empty);
    drop(b);
    fs::remove_dir(root.join("top/a/empty")).unwrap();
    fs::rename(root.join("top/a"), root.join("top/z")).unwrap();
}

#[cfg(windows)]
#[test]
fn a_link_between_folders_is_refused() {
    let scratch = Scratch::new("junction");
    let root = &scratch.0;
    fs::create_dir_all(root.join("secret")).unwrap();
    fs::write(root.join("secret/key"), b"secret").unwrap();
    fs::create_dir_all(root.join("top/real")).unwrap();
    // A link from one folder to another, of the kind that anyone may make.
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(root.join("top").join("to-folder"))
        .arg(root.join("secret"))
        .output();
    if !made.is_ok_and(|output| output.status.success()) {
        return; // this system would not make one
    }
    let top = Held::open(&root.join("top")).unwrap();
    assert_eq!(
        kinds(&top),
        [
            ("real".to_owned(), Found::Folder),
            ("to-folder".to_owned(), Found::Link),
        ]
    );
    assert!(matches!(top.open_folder("to-folder"), Err(Refused::Link)));
    assert!(matches!(top.open_file("to-folder"), Err(Refused::Link)));
    assert!(top.create_file("to-folder").is_err());
    assert!(top.create_folder("to-folder").is_err());
    // The link is taken away as a link: what it leads to stays.
    drop(top);
    fs::remove_dir(root.join("top/to-folder")).unwrap();
    assert!(root.join("secret/key").exists());
}
