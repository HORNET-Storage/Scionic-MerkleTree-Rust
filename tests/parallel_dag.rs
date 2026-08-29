mod support;

use scionic_merkletree::{
    create_dag_custom, create_dag_custom_parallel, create_dag_parallel, create_dag_with_options,
    DagBuildOptions, LeafType, Metadata,
};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use support::{create_fixture, options_4096, TempDir, FIXTURES};

#[test]
fn go_worker_matrix_preserves_every_pinned_fixture_and_owned_proof() {
    let temp = TempDir::new("parallel-matrix").unwrap();
    for fixture in FIXTURES {
        let input = create_fixture(temp.path(), fixture.name).unwrap();
        let sequential = create_dag_with_options(&input, &options_4096()).unwrap();
        assert_eq!(sequential.root().as_str(), fixture.root);
        assert_eq!(sequential.len(), fixture.leaves);
        assert_eq!(sequential.root_leaf().leaf_count(), fixture.leaves as u64);
        assert_eq!(sequential.root_leaf().content_size(), fixture.content_size);
        assert_eq!(sequential.root_leaf().dag_size(), fixture.dag_size);
        assert_eq!(
            sequential
                .leaves()
                .values()
                .filter(|leaf| leaf.leaf_type() == LeafType::Chunk)
                .count(),
            fixture.chunks
        );

        for workers in [0_isize, -1, 1, 2, 4, 8] {
            let options = DagBuildOptions::default()
                .with_chunk_size(4096)
                .unwrap()
                .with_parallel_workers(workers);
            let parallel = create_dag_parallel(&input, &options).unwrap();
            assert_eq!(
                parallel.root().as_str(),
                fixture.root,
                "{} with worker setting {workers}",
                fixture.name
            );
            assert_eq!(parallel, sequential);
            parallel.verify().unwrap();

            let selected = parallel
                .leaves()
                .keys()
                .find(|cid| *cid != parallel.root())
                .unwrap()
                .clone();
            assert_eq!(
                parallel
                    .get_partial(std::slice::from_ref(&selected), true)
                    .unwrap(),
                sequential
                    .get_partial(std::slice::from_ref(&selected), true)
                    .unwrap()
            );
        }

        let automatic_options = DagBuildOptions::default()
            .with_chunk_size(4096)
            .unwrap()
            .with_parallel();
        let automatic = create_dag_parallel(&input, &automatic_options).unwrap();
        assert_eq!(automatic, sequential);
    }
}

#[test]
fn parallel_sync_processor_matches_sequential_metadata_and_coverage() {
    let temp = TempDir::new("parallel-processor").unwrap();
    let input = create_fixture(temp.path(), "flat_directory").unwrap();
    let calls = Arc::new(Mutex::new(BTreeSet::<String>::new()));
    let processor_calls = Arc::clone(&calls);
    let processor = move |_path: &Path,
                          relative_path: &str,
                          _entry: &std::fs::DirEntry,
                          _is_root: bool,
                          leaf_type: LeafType|
          -> Option<Metadata> {
        processor_calls
            .lock()
            .unwrap()
            .insert(relative_path.to_owned());
        Some(Metadata::from([(
            "processed".to_owned(),
            leaf_type.as_str().to_owned(),
        )]))
    };

    let sequential = create_dag_custom(&input, &options_4096(), Some(&processor)).unwrap();
    calls.lock().unwrap().clear();
    let parallel_options = options_4096().with_parallel_workers(4);
    let parallel = create_dag_custom_parallel(&input, &parallel_options, Some(&processor)).unwrap();
    assert_eq!(parallel, sequential);
    assert_eq!(
        *calls.lock().unwrap(),
        [
            "file1.txt".to_owned(),
            "file2.txt".to_owned(),
            "file3.txt".to_owned(),
            "file4.txt".to_owned(),
            "file5.txt".to_owned(),
        ]
        .into_iter()
        .collect()
    );
}
