// Command gowirevectors emits the exact JSON and CBOR bytes that the Go
// Scionic Merkle Tree implementation produces for the deterministic fixtures
// shared by every port, so the Rust crate can assert wire parity against an
// independent oracle instead of against its own round trip.
//
// A Rust encoder/decoder pair that is consistently wrong -- reordered fields,
// nil collapsed to empty -- satisfies any self round trip. Only bytes produced
// by the reference implementation can catch that.
//
// The module requirement is redirected by a local replace directive to the
// sibling scionic-merkletree checkout, so these vectors come from the working
// tree rather than a published release.
//
// Regenerate with:
//
//	cd tools/gowirevectors
//	go mod tidy && go run . ../../tests/vectors/go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"

	scionic "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2/dag"
	"github.com/fxamacker/cbor/v2"
)

type fileSpec struct {
	rel  string // '/'-separated; converted with filepath.FromSlash when written
	size int
}

type fixture struct {
	name  string
	files []fileSpec
}

// Mirrors tests/support/mod.rs create_fixture exactly, which itself mirrors the
// Go library's testutil fixtures: content bytes are 'A' + (i % 26).
func deterministicContent(size int) []byte {
	content := make([]byte, size)
	for i := 0; i < size; i++ {
		content[i] = byte('A' + (i % 26))
	}
	return content
}

var fixtures = []fixture{
	{name: "single_small_file", files: []fileSpec{
		{"small.txt", 1024},
	}},
	{name: "single_large_file", files: []fileSpec{
		{"large.txt", 10 * 1024},
	}},
	{name: "flat_directory", files: []fileSpec{
		{"file1.txt", 512},
		{"file2.txt", 1024},
		{"file3.txt", 768},
		{"file4.txt", 2048},
		{"file5.txt", 256},
	}},
	{name: "nested_directory", files: []fileSpec{
		{"subdir1/file1a.txt", 1024},
		{"subdir1/file1b.txt", 1536},
		{"subdir2/file2a.txt", 1024},
		{"subdir2/file2b.txt", 1536},
	}},
	{name: "deep_hierarchy", files: []fileSpec{
		{"level1/file_at_level_1.txt", 256},
		{"level1/level2/file_at_level_2.txt", 512},
		{"level1/level2/level3/file_at_level_3.txt", 768},
		{"level1/level2/level3/level4/file_at_level_4.txt", 1024},
		{"level1/level2/level3/level4/level5/file_at_level_5.txt", 1280},
	}},
	{name: "mixed_sizes", files: []fileSpec{
		{"tiny.txt", 128},
		{"small.txt", 2048},
		{"medium.txt", 5 * 1024},
		{"large.txt", 15 * 1024},
		{"exact_chunk.txt", 4 * 1024},
	}},
}

// wireStates records which nil-versus-empty states the reference implementation
// can actually put on the wire. A port only has to model states Go can emit.
type wireStates struct {
	contentHashNil    int
	contentHashLens   map[int]int
	contentNil        int
	contentLens       int
	classicRootNil    int
	classicRootLens   map[int]int
	linksNil          int
	linksEmpty        int
	linksNonEmpty     int
	additionalDataNil int
	storedProofsNil   int
	storedProofsEmpty int
	proofSiblingsNil  int
	proofSiblingsLens map[int]int
}

func newWireStates() *wireStates {
	return &wireStates{
		contentHashLens:   map[int]int{},
		classicRootLens:   map[int]int{},
		proofSiblingsLens: map[int]int{},
	}
}

func (w *wireStates) observe(s *scionic.SerializableDag) {
	for _, leaf := range s.Leafs {
		if leaf.ContentHash == nil {
			w.contentHashNil++
		} else {
			w.contentHashLens[len(leaf.ContentHash)]++
		}
		if leaf.Content == nil {
			w.contentNil++
		} else {
			w.contentLens++
		}
		if leaf.ClassicMerkleRoot == nil {
			w.classicRootNil++
		} else {
			w.classicRootLens[len(leaf.ClassicMerkleRoot)]++
		}
		switch {
		case leaf.Links == nil:
			w.linksNil++
		case len(leaf.Links) == 0:
			w.linksEmpty++
		default:
			w.linksNonEmpty++
		}
		if leaf.AdditionalData == nil {
			w.additionalDataNil++
		}
		switch {
		case leaf.StoredProofs == nil:
			w.storedProofsNil++
		case len(leaf.StoredProofs) == 0:
			w.storedProofsEmpty++
		}
		for _, branch := range leaf.StoredProofs {
			if branch == nil || branch.Proof == nil {
				continue
			}
			if branch.Proof.Siblings == nil {
				w.proofSiblingsNil++
			} else {
				w.proofSiblingsLens[len(branch.Proof.Siblings)]++
			}
		}
	}
}

func (w *wireStates) report() {
	fmt.Println("")
	fmt.Println("== nil vs empty states the Go serializer actually emits ==")
	fmt.Printf("ContentHash        nil=%d lens=%s\n", w.contentHashNil, histogram(w.contentHashLens))
	fmt.Printf("Content            nil=%d nonNil=%d\n", w.contentNil, w.contentLens)
	fmt.Printf("ClassicMerkleRoot  nil=%d lens=%s\n", w.classicRootNil, histogram(w.classicRootLens))
	fmt.Printf("Links              nil=%d empty(nonNil)=%d nonEmpty=%d\n", w.linksNil, w.linksEmpty, w.linksNonEmpty)
	fmt.Printf("AdditionalData     nil=%d\n", w.additionalDataNil)
	fmt.Printf("StoredProofs       nil=%d empty(nonNil)=%d\n", w.storedProofsNil, w.storedProofsEmpty)
	fmt.Printf("Proof.Siblings     nil=%d lens=%s\n", w.proofSiblingsNil, histogram(w.proofSiblingsLens))
}

func histogram(m map[int]int) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	out := "{"
	for i, k := range keys {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%d:%d", k, m[k])
	}
	return out + "}"
}

func main() {
	// Deliberately no default. This used to default to a CWD-relative "vectors",
	// so running it from tools/gowirevectors without the argument reported a
	// fully successful regeneration while writing a parallel oracle and leaving
	// the real committed vectors untouched. A silent no-op success is the worst
	// available outcome for the one tool the parity suite treats as ground truth.
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run . <output-dir>")
		fmt.Fprintln(os.Stderr, "  from tools/gowirevectors, that is: go run . ../../tests/vectors/go")
		os.Exit(2)
	}
	outDir := os.Args[1]
	must(os.MkdirAll(outDir, 0o755))

	scionic.SetChunkSize(4096)
	scionic.SetDefaultBatchSize()

	base, err := os.MkdirTemp("", "gowirevectors")
	must(err)
	defer os.RemoveAll(base)

	states := newWireStates()
	builtByName := make(map[string]*scionic.Dag, len(fixtures))

	for _, f := range fixtures {
		// The DAG root leaf takes the directory's base name, so the fixture
		// directory must be named exactly after the fixture.
		dir := filepath.Join(base, f.name)
		for _, spec := range f.files {
			path := filepath.Join(dir, filepath.FromSlash(spec.rel))
			must(os.MkdirAll(filepath.Dir(path), 0o755))
			must(os.WriteFile(path, deterministicContent(spec.size), 0o644))
		}

		built, err := scionic.CreateDag(dir, false)
		must(err)
		must(built.Verify())
		builtByName[f.name] = built

		states.observe(built.ToSerializable())

		jsonBytes, err := built.ToJSON()
		must(err)
		cborBytes, err := built.ToCBOR()
		must(err)

		// Marshalling a Go map is only byte-stable if the encoder imposes an
		// order. Probe it rather than assume it: a port cannot be asked to match
		// bytes the reference itself does not reproduce.
		jsonStable := stable(func() []byte { b, e := built.ToJSON(); must(e); return b }, jsonBytes)
		cborStable := stable(func() []byte { b, e := built.ToCBOR(); must(e); return b }, cborBytes)

		must(os.WriteFile(filepath.Join(outDir, f.name+".json"), jsonBytes, 0o644))
		writeCBORBaseline(filepath.Join(outDir, f.name+".cbor"), cborBytes)

		fmt.Printf("%-20s root=%s leaves=%d json=%dB (stable=%v) cbor=%dB (stable=%v)\n",
			f.name, built.Root, len(built.Leafs), len(jsonBytes), jsonStable, len(cborBytes), cborStable)
	}

	manifest := &packetManifest{Schema: 1}
	for _, f := range fixtures {
		manifest.TransmissionPackets += emitTransmissionCase(outDir, f.name, builtByName[f.name], manifest)
		manifest.DefaultBatches += emitDefaultBatches(outDir, f.name, builtByName[f.name], manifest)
	}

	partial := buildProofBearingPartial(builtByName["flat_directory"])
	states.observe(partial.ToSerializable())
	emitPartialDag(outDir, partial, manifest)
	partialCase := "flat_directory_partial_file1_file3"
	manifest.TransmissionPackets += emitTransmissionCase(outDir, partialCase, partial, manifest)
	manifest.DefaultBatches += emitDefaultBatches(outDir, partialCase, partial, manifest)

	emitCompatibilityVectors(outDir, builtByName["single_small_file"], manifest)
	emitSerializerProbes(outDir, manifest)

	if manifest.TransmissionPackets != 45 {
		panic(fmt.Sprintf("expected 45 transmission packets, got %d", manifest.TransmissionPackets))
	}
	if manifest.DefaultBatches != 7 {
		panic(fmt.Sprintf("expected 7 default batches, got %d", manifest.DefaultBatches))
	}
	if len(manifest.Artifacts) != 59 {
		panic(fmt.Sprintf("expected 59 artifact pairs, got %d", len(manifest.Artifacts)))
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	manifestPath := filepath.Join(outDir, "packets", "manifest.json")
	must(os.MkdirAll(filepath.Dir(manifestPath), 0o755))
	must(os.WriteFile(manifestPath, manifestBytes, 0o644))

	states.report()
	fmt.Printf("\npackets=%d default_batches=%d artifact_pairs=%d\n",
		manifest.TransmissionPackets, manifest.DefaultBatches, len(manifest.Artifacts))
	fmt.Printf("cbor_baselines written=%d preserved=%d\n",
		cborBaselinesWritten, cborBaselinesPreserved)
	fmt.Printf("os=%s library=%s\n", runtime.GOOS, scionicVersion())
}

type encodedPair struct {
	json []byte
	cbor []byte
}

type artifactRecord struct {
	BasePath        string         `json:"base_path"`
	Case            string         `json:"case"`
	Kind            string         `json:"kind"`
	Index           int            `json:"index"`
	LeafHashes      []string       `json:"leaf_hashes"`
	ParentHash      string         `json:"parent_hash,omitempty"`
	Relationships   map[string]string `json:"relationships,omitempty"`
	PacketIndex     int            `json:"packet_index"`
	TotalPackets    int            `json:"total_packets"`
	JSONCompare     string         `json:"json_compare"`
	CBORCompare     string         `json:"cbor_compare"`
	MapCardinalities map[string]int `json:"map_cardinalities"`
	MultiEntryMaps  []string       `json:"multi_entry_maps"`
	Synthetic       bool           `json:"synthetic"`
	LegacyCounters  bool           `json:"legacy_counters,omitempty"`
}

type packetManifest struct {
	Schema              int              `json:"schema"`
	TransmissionPackets int              `json:"transmission_packets"`
	DefaultBatches      int              `json:"default_batches"`
	Artifacts           []artifactRecord `json:"artifacts"`
}

func emitTransmissionCase(outDir, caseName string, source *scionic.Dag, manifest *packetManifest) int {
	packets := source.GetLeafSequence()
	if len(packets) != len(source.Leafs) {
		panic(fmt.Sprintf("%s emitted %d packets for %d leaves", caseName, len(packets), len(source.Leafs)))
	}
	payloads := make([]encodedPair, len(packets))
	for i, packet := range packets {
		jsonBytes, err := packet.ToJSON()
		must(err)
		cborBytes, err := packet.ToCBOR()
		must(err)
		assertTransmissionDecodes(jsonBytes, cborBytes)
		base := filepath.ToSlash(filepath.Join("packets", "transmission", caseName, fmt.Sprintf("%03d", i)))
		writePair(outDir, base, jsonBytes, cborBytes)
		manifest.Artifacts = append(manifest.Artifacts, packetRecord(base, caseName, "transmission", i, packet, false))
		payloads[i] = encodedPair{json: jsonBytes, cbor: cborBytes}
	}
	replayTransmission(source, payloads, true)
	replayTransmission(source, payloads, false)
	return len(packets)
}

func emitDefaultBatches(outDir, caseName string, source *scionic.Dag, manifest *packetManifest) int {
	scionic.SetDefaultBatchSize()
	batches := source.GetBatchedLeafSequence()
	if len(batches) != 1 {
		panic(fmt.Sprintf("%s expected one default batch, got %d", caseName, len(batches)))
	}
	emitBatchSequence(outDir, filepath.Join("packets", "batched", "default", caseName), caseName, "batched-default", source, batches, manifest)
	return len(batches)
}

func emitBatchSequence(outDir, baseDir, caseName, kind string, source *scionic.Dag, batches []*scionic.BatchedTransmissionPacket, manifest *packetManifest) []encodedPair {
	payloads := make([]encodedPair, len(batches))
	for i, batch := range batches {
		jsonBytes, err := batch.ToJSON()
		must(err)
		cborBytes, err := batch.ToCBOR()
		must(err)
		assertBatchDecodes(jsonBytes, cborBytes, batch.PacketIndex, batch.TotalPackets)
		base := filepath.ToSlash(filepath.Join(baseDir, fmt.Sprintf("%03d", i)))
		writePair(outDir, base, jsonBytes, cborBytes)
		manifest.Artifacts = append(manifest.Artifacts, batchRecord(base, caseName, kind, i, batch, false, false))
		payloads[i] = encodedPair{json: jsonBytes, cbor: cborBytes}
	}
	replayBatches(source, payloads, true)
	replayBatches(source, payloads, false)
	return payloads
}

func buildProofBearingPartial(flat *scionic.Dag) *scionic.Dag {
	targets := make([]string, 0, 2)
	for hash, leaf := range flat.Leafs {
		if leaf.Type == scionic.FileLeafType && (leaf.ItemName == "file1.txt" || leaf.ItemName == "file3.txt") {
			targets = append(targets, hash)
		}
	}
	sort.Strings(targets)
	if len(targets) != 2 {
		panic("expected file1.txt and file3.txt")
	}
	partial, err := flat.GetPartial(targets, true)
	must(err)
	must(partial.Verify())
	if !partial.IsPartial() || len(partial.Leafs) != 3 {
		panic("proof-bearing partial must contain exactly three leaves")
	}
	root := partial.Leafs[partial.Root]
	if root.CurrentLinkCount != 5 || len(root.Links) != 2 || len(root.Proofs) != 2 {
		panic("partial root must retain two of five children and two proofs")
	}
	return partial
}

func emitPartialDag(outDir string, partial *scionic.Dag, manifest *packetManifest) {
	jsonBytes, err := partial.ToJSON()
	must(err)
	cborBytes, err := partial.ToCBOR()
	must(err)
	fromJSON, err := scionic.FromJSON(jsonBytes)
	must(err)
	fromCBOR, err := scionic.FromCBOR(cborBytes)
	must(err)
	jsonAgain, err := fromJSON.ToJSON()
	must(err)
	cborAsJSON, err := fromCBOR.ToJSON()
	must(err)
	if !bytes.Equal(jsonAgain, jsonBytes) || !bytes.Equal(cborAsJSON, jsonBytes) {
		panic("partial DAG decode equivalence failed")
	}
	base := "packets/partial/flat_directory_file1_file3.dag"
	writePair(outDir, base, jsonBytes, cborBytes)
	cardinalities := map[string]int{"Leafs": len(partial.Leafs)}
	multi := []string{"Leafs"}
	root := partial.Leafs[partial.Root]
	cardinalities["root.stored_proofs"] = len(root.Proofs)
	if len(root.Proofs) > 1 {
		multi = append(multi, "root.stored_proofs")
	}
	manifest.Artifacts = append(manifest.Artifacts, artifactRecord{
		BasePath: base, Case: "flat_directory_partial_file1_file3", Kind: "partial-dag", Index: 0,
		LeafHashes: sortedDagLeafHashes(partial), JSONCompare: "bytes", CBORCompare: "decoded",
		MapCardinalities: cardinalities, MultiEntryMaps: multi,
	})
}

func emitCompatibilityVectors(outDir string, source *scionic.Dag, manifest *packetManifest) {
	var batches []*scionic.BatchedTransmissionPacket
	func() {
		scionic.SetBatchSize(1)
		defer scionic.SetDefaultBatchSize()
		batches = source.GetBatchedLeafSequence()
	}()
	if len(batches) != 2 || batches[1].PacketIndex != 1 || batches[1].TotalPackets != 2 {
		panic("unexpected size-1 compatibility batches")
	}
	payloads := emitBatchSequence(outDir, filepath.Join("packets", "batched", "size-1", "single_small_file"), "single_small_file", "batched-size-1", source, batches, manifest)

	serial := batches[1].ToSerializable()
	legacy := struct {
		Leaves        []*scionic.SerializableDagLeaf
		Relationships map[string]string
	}{Leaves: serial.Leaves, Relationships: serial.Relationships}
	legacyJSON, err := json.MarshalIndent(legacy, "", "  ")
	must(err)
	legacyCBOR, err := cbor.Marshal(legacy)
	must(err)
	decodedJSON, err := scionic.BatchedTransmissionPacketFromJSON(legacyJSON)
	must(err)
	decodedCBOR, err := scionic.BatchedTransmissionPacketFromCBOR(legacyCBOR)
	must(err)
	if decodedJSON.PacketIndex != 0 || decodedJSON.TotalPackets != 0 || decodedCBOR.PacketIndex != 0 || decodedCBOR.TotalPackets != 0 {
		panic("legacy counters must decode to zero")
	}
	assertCounterKeyPresence(payloads[1].json, payloads[1].cbor, legacyJSON, legacyCBOR)
	base := "packets/batched/compat/legacy-no-counters"
	writePair(outDir, base, legacyJSON, legacyCBOR)
	// These bytes are hand-marshalled from an anonymous struct that drops the
	// counter fields; they are not emitted by the library's own encoder. That is
	// synthetic provenance no matter how faithfully they mimic an older peer, and
	// labelling them library output would let a future reader treat a fabricated
	// shape as evidence of what Go actually produces.
	record := batchRecord(base, "single_small_file", "batched-legacy-probe", 1, decodedJSON, true, true)
	manifest.Artifacts = append(manifest.Artifacts, record)

	mixedJSON := []encodedPair{payloads[0], {json: legacyJSON, cbor: legacyCBOR}}
	replayBatches(source, mixedJSON, true)
	replayBatches(source, mixedJSON, false)
}

func emitSerializerProbes(outDir string, manifest *packetManifest) {
	nilLeaf := &scionic.DagLeaf{
		Hash: "probe", ItemName: "probe", Type: scionic.FileLeafType,
		ContentHash: nil, Content: nil, ClassicMerkleRoot: []byte{},
		Links: nil, AdditionalData: nil, Proofs: nil,
	}
	nilPacket := &scionic.TransmissionPacket{Leaf: nilLeaf, ParentHash: "", Proofs: nil}
	emitPacketProbe(outDir, "packets/probes/transmission-nil", "transmission-nil", nilPacket, manifest)

	emptyContentLeaf := &scionic.DagLeaf{
		Hash: "probe", ItemName: "probe", Type: scionic.FileLeafType,
		ContentHash: nil, Content: []byte{}, ClassicMerkleRoot: []byte{},
		Links: []string{}, AdditionalData: map[string]string{},
		Proofs: map[string]*scionic.ClassicTreeBranch{},
	}
	emptyPacket := &scionic.TransmissionPacket{
		Leaf: emptyContentLeaf, ParentHash: "", Proofs: map[string]*scionic.ClassicTreeBranch{},
	}
	emitPacketProbe(outDir, "packets/probes/transmission-empty-content", "transmission-empty-content", emptyPacket, manifest)

	emptyBatch := &scionic.BatchedTransmissionPacket{Leaves: nil, Relationships: nil}
	jsonBytes, err := emptyBatch.ToJSON()
	must(err)
	cborBytes, err := emptyBatch.ToCBOR()
	must(err)
	base := "packets/probes/batched-empty"
	writePair(outDir, base, jsonBytes, cborBytes)
	manifest.Artifacts = append(manifest.Artifacts, batchRecord(base, "batched-empty", "probe", 0, emptyBatch, true, false))
}

func emitPacketProbe(outDir, base, caseName string, packet *scionic.TransmissionPacket, manifest *packetManifest) {
	jsonBytes, err := packet.ToJSON()
	must(err)
	cborBytes, err := packet.ToCBOR()
	must(err)
	writePair(outDir, base, jsonBytes, cborBytes)
	manifest.Artifacts = append(manifest.Artifacts, packetRecord(base, caseName, "probe", 0, packet, true))
}

func assertTransmissionDecodes(jsonBytes, cborBytes []byte) {
	fromJSON, err := scionic.TransmissionPacketFromJSON(jsonBytes)
	must(err)
	fromCBOR, err := scionic.TransmissionPacketFromCBOR(cborBytes)
	must(err)
	jsonAgain, err := fromJSON.ToJSON()
	must(err)
	cborAsJSON, err := fromCBOR.ToJSON()
	must(err)
	if !bytes.Equal(jsonAgain, jsonBytes) || !bytes.Equal(cborAsJSON, jsonBytes) {
		panic("transmission packet decode equivalence failed")
	}
}

func assertBatchDecodes(jsonBytes, cborBytes []byte, index, total int) {
	fromJSON, err := scionic.BatchedTransmissionPacketFromJSON(jsonBytes)
	must(err)
	fromCBOR, err := scionic.BatchedTransmissionPacketFromCBOR(cborBytes)
	must(err)
	if fromJSON.PacketIndex != index || fromJSON.TotalPackets != total || fromCBOR.PacketIndex != index || fromCBOR.TotalPackets != total {
		panic("batched packet counter decode mismatch")
	}
	jsonAgain, err := fromJSON.ToJSON()
	must(err)
	cborAsJSON, err := fromCBOR.ToJSON()
	must(err)
	if !bytes.Equal(jsonAgain, jsonBytes) || !bytes.Equal(cborAsJSON, jsonBytes) {
		panic("batched packet decode equivalence failed")
	}
}

func replayTransmission(source *scionic.Dag, payloads []encodedPair, useJSON bool) {
	receiver := &scionic.Dag{Root: source.Root, Leafs: map[string]*scionic.DagLeaf{}}
	for _, payload := range payloads {
		var packet *scionic.TransmissionPacket
		var err error
		if useJSON {
			packet, err = scionic.TransmissionPacketFromJSON(payload.json)
		} else {
			packet, err = scionic.TransmissionPacketFromCBOR(payload.cbor)
		}
		must(err)
		must(receiver.ApplyAndVerifyTransmissionPacket(packet))
	}
	must(receiver.Verify())
	if receiver.Root != source.Root || len(receiver.Leafs) != len(source.Leafs) {
		panic("transmission replay did not reconstruct the source DAG")
	}
}

func replayBatches(source *scionic.Dag, payloads []encodedPair, useJSON bool) {
	receiver := &scionic.Dag{Root: source.Root, Leafs: map[string]*scionic.DagLeaf{}}
	for _, payload := range payloads {
		var packet *scionic.BatchedTransmissionPacket
		var err error
		if useJSON {
			packet, err = scionic.BatchedTransmissionPacketFromJSON(payload.json)
		} else {
			packet, err = scionic.BatchedTransmissionPacketFromCBOR(payload.cbor)
		}
		must(err)
		must(receiver.ApplyAndVerifyBatchedTransmissionPacket(packet))
	}
	must(receiver.Verify())
	if receiver.Root != source.Root || len(receiver.Leafs) != len(source.Leafs) {
		panic("batched replay did not reconstruct the source DAG")
	}
}

func assertCounterKeyPresence(currentJSON, currentCBOR, legacyJSON, legacyCBOR []byte) {
	var currentJSONMap map[string]json.RawMessage
	var legacyJSONMap map[string]json.RawMessage
	must(json.Unmarshal(currentJSON, &currentJSONMap))
	must(json.Unmarshal(legacyJSON, &legacyJSONMap))
	if currentJSONMap["PacketIndex"] == nil || currentJSONMap["TotalPackets"] == nil || legacyJSONMap["PacketIndex"] != nil || legacyJSONMap["TotalPackets"] != nil {
		panic("JSON counter key presence mismatch")
	}
	var currentCBORMap map[string]any
	var legacyCBORMap map[string]any
	must(cbor.Unmarshal(currentCBOR, &currentCBORMap))
	must(cbor.Unmarshal(legacyCBOR, &legacyCBORMap))
	if _, ok := currentCBORMap["PacketIndex"]; !ok { panic("current CBOR missing PacketIndex") }
	if _, ok := currentCBORMap["TotalPackets"]; !ok { panic("current CBOR missing TotalPackets") }
	if _, ok := legacyCBORMap["PacketIndex"]; ok { panic("legacy CBOR has PacketIndex") }
	if _, ok := legacyCBORMap["TotalPackets"]; ok { panic("legacy CBOR has TotalPackets") }
}

func packetRecord(base, caseName, kind string, index int, packet *scionic.TransmissionPacket, synthetic bool) artifactRecord {
	serial := packet.ToSerializable()
	cardinalities := map[string]int{
		"proofs": len(serial.Proofs),
		"Leaf.AdditionalData": len(serial.Leaf.AdditionalData),
		"Leaf.stored_proofs": len(serial.Leaf.StoredProofs),
	}
	multi := multiEntryMapNames(cardinalities)
	return artifactRecord{
		BasePath: base, Case: caseName, Kind: kind, Index: index,
		LeafHashes: []string{packet.Leaf.Hash}, ParentHash: packet.ParentHash,
		PacketIndex: index, TotalPackets: 0, JSONCompare: "bytes", CBORCompare: "decoded",
		MapCardinalities: cardinalities, MultiEntryMaps: multi, Synthetic: synthetic,
	}
}

func batchRecord(base, caseName, kind string, index int, packet *scionic.BatchedTransmissionPacket, synthetic, legacy bool) artifactRecord {
	serial := packet.ToSerializable()
	cardinalities := map[string]int{"Relationships": len(serial.Relationships)}
	leafHashes := make([]string, len(serial.Leaves))
	for i, leaf := range serial.Leaves {
		leafHashes[i] = leaf.Hash
		cardinalities[fmt.Sprintf("Leaves[%d].AdditionalData", i)] = len(leaf.AdditionalData)
		cardinalities[fmt.Sprintf("Leaves[%d].stored_proofs", i)] = len(leaf.StoredProofs)
	}
	return artifactRecord{
		BasePath: base, Case: caseName, Kind: kind, Index: index, LeafHashes: leafHashes,
		Relationships: serial.Relationships, PacketIndex: packet.PacketIndex, TotalPackets: packet.TotalPackets,
		JSONCompare: "bytes", CBORCompare: "decoded", MapCardinalities: cardinalities,
		MultiEntryMaps: multiEntryMapNames(cardinalities), Synthetic: synthetic, LegacyCounters: legacy,
	}
}

func multiEntryMapNames(cardinalities map[string]int) []string {
	names := make([]string, 0)
	for name, count := range cardinalities {
		if count > 1 { names = append(names, name) }
	}
	sort.Strings(names)
	return names
}

func sortedDagLeafHashes(dag *scionic.Dag) []string {
	hashes := make([]string, 0, len(dag.Leafs))
	for hash := range dag.Leafs { hashes = append(hashes, hash) }
	sort.Strings(hashes)
	return hashes
}

func writePair(outDir, base string, jsonBytes, cborBytes []byte) {
	jsonPath := filepath.Join(outDir, filepath.FromSlash(base+".json"))
	cborPath := filepath.Join(outDir, filepath.FromSlash(base+".cbor"))
	must(os.MkdirAll(filepath.Dir(jsonPath), 0o755))
	must(os.WriteFile(jsonPath, jsonBytes, 0o644))
	writeCBORBaseline(cborPath, cborBytes)
}

var (
	cborBaselinesWritten   int
	cborBaselinesPreserved int
)

// writeCBORBaseline writes a CBOR baseline only when one does not already exist.
//
// Go's CBOR encoder walks Go maps in nondeterministic order, so ToCBOR output is
// byte-unstable for any value holding a multi-entry map -- every DAG fixture
// above measures stable=false. Rewriting an existing baseline would therefore
// churn bytes on every run without adding information, and would bury a genuine
// encoding change inside that noise. Keep the first baseline and assert instead
// that the fresh encoding still carries the same content; the Rust side compares
// CBOR by decode-equivalence for exactly the same reason.
func writeCBORBaseline(path string, encoded []byte) {
	existing, err := os.ReadFile(path)
	if err != nil {
		must(os.MkdirAll(filepath.Dir(path), 0o755))
		must(os.WriteFile(path, encoded, 0o644))
		cborBaselinesWritten++
		return
	}
	if !bytes.Equal(existing, encoded) {
		assertSameCBORContent(path, existing, encoded)
	}
	cborBaselinesPreserved++
}

// assertSameCBORContent compares two encodings by decoded value, which ignores
// map ordering but still fails on any real content drift.
func assertSameCBORContent(path string, existing, fresh []byte) {
	var before, after any
	must(cbor.Unmarshal(existing, &before))
	must(cbor.Unmarshal(fresh, &after))
	if !reflect.DeepEqual(before, after) {
		panic(fmt.Sprintf("%s: regenerated CBOR differs in content, not just map order", path))
	}
}

// stable re-encodes several times and reports whether every encoding matched
// the first one.
func stable(encode func() []byte, first []byte) bool {
	for i := 0; i < 8; i++ {
		if !bytes.Equal(encode(), first) {
			return false
		}
	}
	return true
}

func scionicVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path != "github.com/HORNET-Storage/Scionic-Merkle-Tree/v2" {
			continue
		}
		// A replaced module still reports the required version here, which would
		// credit these vectors to a published release they did not come from.
		if dep.Replace != nil {
			return fmt.Sprintf("%s (replaced by %s)", dep.Version, dep.Replace.Path)
		}
		return dep.Version
	}
	return "unknown"
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

