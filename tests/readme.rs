//! The README is held to the crate, so that it cannot fall behind it: the
//! version it names, the examples it tells a reader to run, and the files it
//! points to. Its Rust examples are compiled with the documentation tests.

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
