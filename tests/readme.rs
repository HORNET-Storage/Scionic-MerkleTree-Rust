//! The README is held to the crate, so that it cannot fall behind it: the
//! version it names, the examples it tells a reader to run, the files it
//! points to, and the three pictures it shows. Its Rust examples are compiled
//! with the documentation tests.

use std::path::Path;

const README: &str = include_str!("../README.md");

#[test]
fn the_readme_names_this_version() {
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        README.contains(&format!("version-{version}-")),
        "the badge at the top names version {version}"
    );
    assert!(
        README.contains(&format!("version {version}")),
        "the text names version {version}"
    );
    assert!(
        README.contains(&format!("What's New in {version}")),
        "what is new is told for version {version}"
    );
    assert!(
        README.contains(&format!("scionic-merkletree = \"{version}\"")),
        "the line that installs the crate names version {version}"
    );
    let oldest = env!("CARGO_PKG_RUST_VERSION");
    assert!(
        README.contains(&format!("rustc-{oldest}%2B"))
            && README.contains(&format!("Rust {oldest}")),
        "the oldest Rust the crate supports is {oldest}"
    );
}

#[test]
fn every_example_the_readme_runs_is_there() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    // Each `cargo run --release --example <name>` names an example.
    let mut named = 0;
    for after in README.split("--example ").skip(1) {
        let name = after.split_whitespace().next().unwrap_or_default();
        assert!(
            examples.join(format!("{name}.rs")).is_file(),
            "the README runs an example that is not there: {name}"
        );
        named += 1;
    }
    assert!(named >= 3, "the README runs the crate's examples");
    // And every example the crate has is one the README tells of.
    for entry in std::fs::read_dir(&examples).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        assert!(
            README.contains(&format!("examples/{name}")),
            "the README does not tell of examples/{name}"
        );
    }
}

#[test]
fn every_file_the_readme_points_to_is_there() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut links = 0;
    for target in README.split("](").skip(1) {
        let target = target.split(')').next().unwrap_or_default();
        if target.starts_with("http") || target.starts_with('#') {
            continue;
        }
        assert!(
            root.join(target).exists(),
            "the README points to a file that is not there: {target}"
        );
        links += 1;
    }
    assert!(links >= 10, "the README points into the repository");
}

/// The README's three pictures are its author's own, and stay through every
/// rewrite of the text around them: the one under the opening, and the two
/// that have a heading each. Which picture stands there is the author's to
/// change, so this holds the places and not the pictures.
#[test]
fn the_readme_keeps_its_pictures() {
    // Line endings are whatever the checkout gave.
    let text = README.replace("\r\n", "\n");
    let (opening, _) = text
        .split_once("\n## Contents\n")
        .expect("the README has a list of its contents");
    assert!(
        opening.contains("\n!["),
        "the README has no picture under its opening"
    );
    for heading in ["### Scionic Merkle Tree", "### Scionic Merkle Branch"] {
        let under = text
            .split_once(&format!("\n{heading}\n"))
            .map(|(_, after)| after.trim_start_matches('\n'));
        assert!(
            under.is_some_and(|after| after.starts_with("![")),
            "the README has no picture under {heading:?}"
        );
    }
}

/// A picture that the README takes from the repository is a picture: a PNG
/// from its first bytes to its last, and wide enough to be read at the width
/// of a page.
#[test]
fn the_pictures_the_readme_shows_are_pictures() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let text = README.replace("\r\n", "\n");
    let mut pictures = 0;
    for after in text.split("\n![").skip(1) {
        let Some((_, rest)) = after.split_once("](") else {
            continue;
        };
        let Some((target, _)) = rest.split_once(')') else {
            continue;
        };
        if target.starts_with("http") {
            continue;
        }
        let bytes = std::fs::read(root.join(target)).unwrap();
        // A PNG begins with eight bytes of its own and the header that says
        // how large the picture is, and it ends with twelve bytes of its own.
        assert!(
            bytes.len() > 45
                && bytes.starts_with(b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR")
                && bytes.ends_with(b"\x00\x00\x00\x00IEND\xae\x42\x60\x82"),
            "{target} is not a picture"
        );
        let width = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
        assert!(
            width >= 1600,
            "{target} is {width} pixels wide, too few to read"
        );
        pictures += 1;
    }
    assert_eq!(pictures, 3, "the README shows its three pictures");
}
