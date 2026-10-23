//go:build pgtest

package postgres

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"

	"go.kenn.io/agentsview/internal/db"
	"go.kenn.io/agentsview/internal/storage"
	"go.kenn.io/agentsview/internal/vector"
)

func TestVectorHubPushPublishesCompatibility(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_metadata_test")
	seedVectorSession(t, local, "A")
	sync.vectorSource = hubRecipeSource("hub-metadata", map[string]string{"max_input_chars": "8192"})
	_, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	var version int
	var automated bool
	require.NoError(t, pg.QueryRow(`SELECT data_version, include_automated FROM vector_generation_machines`).Scan(&version, &automated))
	assert.Equal(t, db.CurrentDataVersion(), version)
	assert.False(t, automated)
	source := hubRecipeSource("hub-metadata", map[string]string{"max_input_chars": "8192"})
	includeAutomated := true
	source.gen.IncludeAutomated = &includeAutomated
	sync.vectorSource = source
	_, err = sync.Push(t.Context(), true, nil)
	require.NoError(t, err)
	require.NoError(t, pg.QueryRow(`SELECT data_version, include_automated FROM vector_generation_machines`).Scan(&version, &automated))
	assert.True(t, automated)
}

func TestVectorHubLookupRoundTrip(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_lookup_test")
	source := hubRecipeSource("hub-lookup", map[string]string{"max_input_chars": "8192"})
	type fixture struct {
		identity vector.HubIdentity
		values   []float32
	}
	var fixtures []fixture
	for _, session := range []string{"A", "B"} {
		seedVectorSession(t, local, session)
		source.hashes[session] = "corpus"
		source.docs[session] = nil
		for i := 0; i < 64; i++ {
			kind, prefix, uuid, occurrence := "user", "u:", fmt.Sprintf("unit-%d", i), 1
			if i%2 == 1 {
				kind, prefix = "run", "r:"
			}
			if i%4 == 2 {
				occurrence = 2
			}
			key := fmt.Sprintf("%s%s:%s", prefix, session, uuid)
			if occurrence == 2 {
				key += "#2"
			}
			if i%4 == 3 {
				uuid = ""
				key = fmt.Sprintf("ro:%s:%d", session, i)
			}
			values := []float32{float32(i) / 32, -float32(i) / 32, 0.1, 1}
			doc := vdoc(session, key, i, "content", fmt.Sprint(i), values)
			doc.SourceUUID = uuid
			source.docs[session] = append(source.docs[session], doc)
			// PG halfvec rounds 0.1 to this exact float32 value.
			fixtures = append(fixtures, fixture{vector.HubIdentity{SessionID: session, UnitKind: kind, SourceUUID: uuid, Occurrence: occurrence, Ordinal: i, ContentHash: fmt.Sprint(i)}, []float32{values[0], values[1], 0.0999755859375, 1}})
		}
	}
	sync.vectorSource = source
	_, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	_, err = pg.Exec(`DELETE FROM vector_push_state WHERE session_id='B'`)
	require.NoError(t, err)
	id, _, ok, err := LookupVectorGeneration(t.Context(), pg, "hub-lookup")
	require.NoError(t, err)
	require.True(t, ok)
	store := &Store{pg: pg}
	setHubTestSearcher(t, store, id)
	hegel.Test(t, func(ht *hegel.T) {
		f := fixtures[hegel.Draw(ht, hegel.Integers(0, len(fixtures)-1))]
		stale := hegel.Draw(ht, hegel.Booleans())
		identity := f.identity
		if stale {
			identity.ContentHash = "stale"
		}
		reply, err := store.LookupHubVectors(ht.Context(), vector.HubLookupRequest{Fingerprint: "hub-lookup", Identities: []vector.HubIdentity{identity}})
		require.NoError(ht, err)
		require.Equal(ht, vector.HubVectorVersion, reply.Version)
		if stale || identity.SessionID == "B" {
			require.Equal(ht, []int{0}, reply.Absent)
			require.Empty(ht, reply.Chunks)
			return
		}
		require.Empty(ht, reply.Absent)
		require.Len(ht, reply.Chunks, 1)
		require.Equal(ht, 0, reply.Chunks[0].Index)
		require.Equal(ht, 1, reply.Chunks[0].ChunkCount)
		got, err := vector.DecodeHubVector(reply.Chunks[0].Vector, 4)
		require.NoError(ht, err)
		require.Equal(ht, f.values, got)
	}, hegel.WithTestCases(1000))
	generation, err := store.HubVectorGeneration(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "hub-lookup", generation.Fingerprint)
	assert.Equal(t, db.CurrentDataVersion(), generation.DataVersion)
	_, err = store.LookupHubVectors(t.Context(), vector.HubLookupRequest{Fingerprint: "other", Identities: []vector.HubIdentity{{SessionID: "A", UnitKind: "user", ContentHash: "x"}}})
	assert.ErrorIs(t, err, vector.ErrHubGenerationChanged)
}

func TestVectorHubLookupPagination(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_pages_test")
	seedVectorSession(t, local, "A")
	source := hubRecipeSource("pages", map[string]string{"max_input_chars": "8192"})
	doc := vdoc("A", "o:A:0", 0, "content", "hash")
	for i := 0; i < 40; i++ {
		doc.Chunks = append(doc.Chunks, storage.VectorPushChunk{ChunkIndex: i, Embedding: []float32{1, 0, 0, 0}})
	}
	source.docs["A"] = []storage.VectorPushDoc{doc}
	sync.vectorSource = source
	_, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	id, _, _, err := LookupVectorGeneration(t.Context(), pg, "pages")
	require.NoError(t, err)
	store := &Store{pg: pg}
	setHubTestSearcher(t, store, id)
	req := vector.HubLookupRequest{Fingerprint: "pages", Identities: []vector.HubIdentity{{SessionID: "A", UnitKind: "user", ContentHash: "hash"}}}
	total := 0
	pages := 0
	for {
		reply, err := store.lookupHubVectors(t.Context(), req, 2300)
		require.NoError(t, err)
		encoded, err := json.Marshal(reply)
		require.NoError(t, err)
		require.LessOrEqual(t, len(encoded), 2300)
		for _, chunk := range reply.Chunks {
			require.Equal(t, total, chunk.ChunkIndex)
			require.Equal(t, 40, chunk.ChunkCount)
			total++
		}
		pages++
		require.Less(t, pages, 41)
		if reply.NextCursor == "" {
			break
		}
		req.Cursor = reply.NextCursor
	}
	assert.Equal(t, 40, total)
	assert.Greater(t, pages, 1)
	req.Identities[0].ContentHash = "changed"
	_, err = store.LookupHubVectors(t.Context(), req)
	assert.ErrorIs(t, err, vector.ErrHubLookupInvalid)
	generation, err := store.HubVectorGeneration(t.Context())
	require.NoError(t, err)
	assert.Empty(t, generation.Unavailable)
	_, err = pg.Exec(`INSERT INTO vector_generation_machines(generation_id,machine,data_version,include_automated) VALUES($1,'other',$2,true)`, id, db.CurrentDataVersion())
	require.NoError(t, err)
	generation, err = store.HubVectorGeneration(t.Context())
	require.NoError(t, err)
	assert.NotEmpty(t, generation.Unavailable)
}

func TestVectorHubLookupSparseChunks(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_sparse_test")
	seedVectorSession(t, local, "A")
	source := hubRecipeSource("sparse", map[string]string{"max_input_chars": "8192"})
	source.docs["A"] = []storage.VectorPushDoc{vdoc("A", "o:A:0", 0, "content", "hash", []float32{1, 0, 0, 0})}
	sync.vectorSource = source
	_, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	id, _, _, err := LookupVectorGeneration(t.Context(), pg, "sparse")
	require.NoError(t, err)
	store := &Store{pg: pg}
	setHubTestSearcher(t, store, id)
	table := vectorChunkTable(id)
	identity := vector.HubIdentity{SessionID: "A", UnitKind: "user", ContentHash: "hash"}
	hegel.Test(t, func(ht *hegel.T) {
		// Bound the materialized document size while drawing the full stored index domain.
		n := 1 + hegel.Draw(ht, hegel.Integers(0, math.MaxInt32))%8
		indices := make([]int, n)
		for i := range indices {
			indices[i] = hegel.Draw(ht, hegel.Integers(0, math.MaxInt32))
		}
		slices.Sort(indices)
		indices = slices.Compact(indices)
		switch hegel.Draw(ht, hegel.Integers(0, 4)) {
		case 0:
			indices = []int{0, 2}
		case 1:
			indices = []int{3, 7, 15}
		case 2:
			indices = []int{42}
		}
		_, err := pg.ExecContext(ht.Context(), "DELETE FROM "+table)
		require.NoError(ht, err)
		expected := make([]vector.HubChunk, len(indices))
		for i, index := range indices {
			_, err = pg.ExecContext(ht.Context(), fmt.Sprintf("INSERT INTO %s (doc_key,chunk_index,embedding) VALUES ('o:A:0',$1,$2)", table), index, fmt.Sprintf("[%d,0,0,0]", i+1))
			require.NoError(ht, err)
			encoded, err := vector.EncodeHubVector([]float32{float32(i + 1), 0, 0, 0})
			require.NoError(ht, err)
			expected[i] = vector.HubChunk{Index: 0, ChunkIndex: index, ChunkCount: len(indices), Vector: encoded}
		}
		req := vector.HubLookupRequest{Fingerprint: "sparse", Identities: []vector.HubIdentity{identity}}
		full, err := store.LookupHubVectors(ht.Context(), req)
		require.NoError(ht, err)
		require.Equal(ht, expected, full.Chunks)
		// Repeated and absent identities exercise resets between sparse documents.
		missing := identity
		missing.ContentHash = "missing"
		req.Identities = []vector.HubIdentity{missing, identity, missing, identity}
		var actual []vector.HubChunk
		var absent []int
		for pages := 0; ; pages++ {
			require.Less(ht, pages, 2*len(indices)+4)
			page, err := store.lookupHubVectors(ht.Context(), req, 2200)
			require.NoError(ht, err)
			actual = append(actual, page.Chunks...)
			absent = append(absent, page.Absent...)
			if page.NextCursor == "" {
				break
			}
			require.NotEqual(ht, req.Cursor, page.NextCursor)
			req.Cursor = page.NextCursor
		}
		want := make([]vector.HubChunk, 0, 2*len(expected))
		for _, position := range []int{1, 3} {
			for _, chunk := range expected {
				chunk.Index = position
				want = append(want, chunk)
			}
		}
		require.Equal(ht, want, actual)
		require.Equal(ht, []int{0, 2}, absent)
	}, hegel.WithTestCases(1000))
}

func TestVectorHubRejectsNegativeChunkIndex(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_negative_test")
	seedVectorSession(t, local, "A")
	source := hubRecipeSource("negative", map[string]string{"max_input_chars": "8192"})
	source.docs["A"] = []storage.VectorPushDoc{vdoc("A", "o:A:0", 0, "content", "hash", []float32{1, 0, 0, 0})}
	sync.vectorSource = source
	_, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	id, _, _, err := LookupVectorGeneration(t.Context(), pg, "negative")
	require.NoError(t, err)
	store := &Store{pg: pg}
	setHubTestSearcher(t, store, id)
	_, err = pg.ExecContext(t.Context(), fmt.Sprintf("UPDATE %s SET chunk_index=-1", vectorChunkTable(id)))
	require.NoError(t, err)
	identity := vector.HubIdentity{SessionID: "A", UnitKind: "user", ContentHash: "hash"}
	_, err = store.LookupHubVectors(t.Context(), vector.HubLookupRequest{Fingerprint: "negative", Identities: []vector.HubIdentity{identity}})
	require.EqualError(t, err, "invalid vector chunk sequence")
}

func TestVectorHubRejectsCrossGenerationRevision(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_revision_test")
	seedVectorSession(t, local, "A")
	identities := []vector.HubIdentity{
		{SessionID: "A", UnitKind: "user", Ordinal: 0, ContentHash: "new-hash"},
		{SessionID: "A", UnitKind: "user", SourceUUID: "uuid", Occurrence: 2, Ordinal: 1, ContentHash: "new-hash"},
		{SessionID: "A", UnitKind: "run", SourceUUID: "run", Occurrence: 1, Ordinal: 2, ContentHash: "new-hash"},
	}
	first := hubRecipeSource("old", map[string]string{"max_input_chars": "8192"})
	first.docs["A"] = nil
	for i, key := range []string{"o:A:0", "u:A:uuid#2", "r:A:run"} {
		doc := vdoc("A", key, i, "old-content", "old-hash", []float32{1, 0, 0, 0})
		doc.SourceUUID = identities[i].SourceUUID
		first.docs["A"] = append(first.docs["A"], doc)
	}
	sync.vectorSource = first
	_, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	id, _, _, err := LookupVectorGeneration(t.Context(), pg, "old")
	require.NoError(t, err)
	store := &Store{pg: pg}
	setHubTestSearcher(t, store, id)
	second := hubRecipeSource("new", map[string]string{"max_input_chars": "8192"})
	second.docs = first.docs
	sync.vectorSource = second
	_, err = sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	identity := identities[0]
	identity.ContentHash = "old-hash"
	reply, err := store.LookupHubVectors(t.Context(), vector.HubLookupRequest{Fingerprint: "old", Identities: []vector.HubIdentity{identity}})
	require.NoError(t, err)
	require.Len(t, reply.Chunks, 1, "equal corpus remains covered in both generations")
	var oldChunks int
	require.NoError(t, pg.QueryRow(`SELECT count(*) FROM `+vectorChunkTable(id)).Scan(&oldChunks))
	assert.Equal(t, len(identities), oldChunks, "unchanged coverage preserves old generation chunks")
	second.hashes["A"] = "changed-corpus"
	for i := range second.docs["A"] {
		second.docs["A"][i].ContentHash = "new-hash"
		second.docs["A"][i].Chunks[0].Embedding = []float32{0, 1, 0, 0}
	}
	_, err = sync.Push(t.Context(), false, nil)
	require.NoError(t, err)

	for _, identity := range identities {
		for _, hash := range []string{"old-hash", "new-hash"} {
			identity.ContentHash = hash
			reply, err := store.LookupHubVectors(t.Context(), vector.HubLookupRequest{Fingerprint: "old", Identities: []vector.HubIdentity{identity}})
			require.NoError(t, err)
			assert.Empty(t, reply.Chunks)
			assert.Equal(t, []int{0}, reply.Absent)
		}
	}

	require.NoError(t, pg.QueryRow(`SELECT count(*) FROM `+vectorChunkTable(id)).Scan(&oldChunks))
	assert.Zero(t, oldChunks, "invalidated coverage must not leave searchable old chunks")
	newID, _, _, err := LookupVectorGeneration(t.Context(), pg, "new")
	require.NoError(t, err)
	var newChunks int
	require.NoError(t, pg.QueryRow(`SELECT count(*) FROM `+vectorChunkTable(newID)).Scan(&newChunks))
	assert.Equal(t, len(identities), newChunks, "current generation chunks remain intact")
	delete(second.hashes, "A")
	delete(second.docs, "A")
	_, err = sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	var documents int
	require.NoError(t, pg.QueryRow(`SELECT count(*) FROM vector_documents WHERE session_id='A'`).Scan(&documents))
	assert.Zero(t, documents, "scope eviction removes shared documents once all chunks are gone")

}

func TestVectorHubLookupCompatibilityGate(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_lookup_gate_test")
	seedVectorSession(t, local, "A")
	source := hubRecipeSource("lookup-gate", map[string]string{"max_input_chars": "8192"})
	source.docs["A"] = []storage.VectorPushDoc{vdoc("A", "u:A:unit", 0, "content", "hash", []float32{1, 0, 0, 0})}
	source.docs["A"][0].SourceUUID = "unit"
	sync.vectorSource = source
	result, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	store := &Store{pg: pg}
	setHubTestSearcher(t, store, result.Vectors.GenerationID)
	hegel.Test(t, func(ht *hegel.T) {
		_, err := pg.ExecContext(ht.Context(), "DELETE FROM vector_generation_machines")
		require.NoError(ht, err)
		n := hegel.Draw(ht, hegel.Integers(0, math.MaxInt32)) % 5
		agree := hegel.Draw(ht, hegel.Booleans())
		commonVersion := hegel.Draw(ht, hegel.Integers(1, math.MaxInt32))
		commonScope := hegel.Draw(ht, hegel.Booleans())
		params := []string{`{"max_input_chars":"8192"}`, "null", "[]", `{"max_input_chars":8192}`}
		paramClass := hegel.Draw(ht, hegel.Integers(0, len(params)-1))
		_, err = pg.ExecContext(ht.Context(), "UPDATE vector_generations SET params=$2::jsonb WHERE id=$1", result.Vectors.GenerationID, params[paramClass])
		require.NoError(ht, err)
		available := n > 0 && paramClass == 0
		var firstVersion int
		var firstScope bool
		for i := range n {
			version := hegel.Draw(ht, hegel.Integers(math.MinInt32, math.MaxInt32))
			if hegel.Draw(ht, hegel.Booleans()) {
				version = db.CurrentDataVersion()
			}
			scope := hegel.Draw(ht, hegel.Booleans())
			var storedVersion *int
			if hegel.Draw(ht, hegel.Booleans()) {
				storedVersion = &version
			}
			var storedScope *bool
			if hegel.Draw(ht, hegel.Booleans()) {
				storedScope = &scope
			}
			if agree {
				version, scope = commonVersion, commonScope
				storedVersion, storedScope = &version, &scope
			}
			_, err = pg.ExecContext(ht.Context(), `INSERT INTO vector_generation_machines
			(generation_id,machine,last_push_at,data_version,include_automated) VALUES ($1,$2,now(),$3,$4)`,
				result.Vectors.GenerationID, strconv.Itoa(i), storedVersion, storedScope)
			require.NoError(ht, err)
			available = available && storedVersion != nil && version > 0 && storedScope != nil &&
				(i == 0 || version == firstVersion && scope == firstScope)
			if i == 0 {
				firstVersion, firstScope = version, scope
			}
		}
		identity := vector.HubIdentity{SessionID: "A", UnitKind: "user", SourceUUID: "unit", Occurrence: 1, ContentHash: "hash"}
		absent := hegel.Draw(ht, hegel.Booleans())
		if absent {
			identity.ContentHash = "different"
		}
		req := vector.HubLookupRequest{Fingerprint: "lookup-gate", Identities: []vector.HubIdentity{identity}}
		if hegel.Draw(ht, hegel.Booleans()) {
			req.Cursor = makeHubLookupCursor(req, 0, 0)
		}
		// Lookup must enforce this policy without a preceding discovery request.
		reply, err := store.LookupHubVectors(ht.Context(), req)
		generation, discoveryErr := store.HubVectorGeneration(ht.Context())
		require.NoError(ht, discoveryErr)
		require.Equal(ht, available, generation.Unavailable == "")
		if !available {
			require.ErrorIs(ht, err, vector.ErrHubGenerationChanged)
			require.Empty(ht, reply.Chunks)
			return
		}
		require.NoError(ht, err)
		if absent {
			require.Equal(ht, []int{0}, reply.Absent)
			require.Empty(ht, reply.Chunks)
		} else {
			require.Empty(ht, reply.Absent)
			require.Len(ht, reply.Chunks, 1)
			values, err := vector.DecodeHubVector(reply.Chunks[0].Vector, 4)
			require.NoError(ht, err)
			require.Equal(ht, []float32{1, 0, 0, 0}, values)
		}
	}, hegel.WithTestCases(1000))
}

func TestVectorHubCompatibilityWitnessTrust(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_witness_test")
	seedVectorSession(t, local, "A")
	source := hubRecipeSource("witness-trust", map[string]string{"max_input_chars": "8192"})
	sync.vectorSource = source
	result, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	key, err := sync.vectorGenerationWitnessKey(t.Context())
	require.NoError(t, err)
	hegel.Test(t, func(ht *hegel.T) {
		version := hegel.Draw(ht, hegel.Integers(math.MinInt32, math.MaxInt32))
		if hegel.Draw(ht, hegel.Booleans()) {
			version = db.CurrentDataVersion()
		}
		var storedVersion *int
		if hegel.Draw(ht, hegel.Booleans()) {
			storedVersion = &version
		}
		var storedScope *bool
		if hegel.Draw(ht, hegel.Booleans()) {
			value := hegel.Draw(ht, hegel.Booleans())
			storedScope = &value
		}
		var requestedScope *bool
		if hegel.Draw(ht, hegel.Booleans()) {
			value := hegel.Draw(ht, hegel.Booleans())
			requestedScope = &value
		}
		missing := hegel.Draw(ht, hegel.Booleans())
		_, err := pg.ExecContext(ht.Context(), "DELETE FROM vector_generation_machines")
		require.NoError(ht, err)
		if !missing {
			_, err = pg.ExecContext(ht.Context(), `INSERT INTO vector_generation_machines
			(generation_id,machine,last_push_at,data_version,include_automated) VALUES ($1,$2,now(),$3,$4)`,
				result.Vectors.GenerationID, key, storedVersion, storedScope)
			require.NoError(ht, err)
		}
		info := source.gen
		info.IncludeAutomated = requestedScope
		resolved, err := sync.resolveVectorGeneration(ht.Context(), info, key)
		require.NoError(ht, err)
		lookedUp, found, err := sync.lookupVectorGeneration(ht.Context(), info.Fingerprint, key, requestedScope)
		require.NoError(ht, err)
		require.True(ht, found)
		sameScope := storedScope == nil && requestedScope == nil || storedScope != nil && requestedScope != nil && *storedScope == *requestedScope
		expected := !missing && storedVersion != nil && *storedVersion == db.CurrentDataVersion() && sameScope
		require.Equal(ht, expected, resolved.machineRecorded)
		require.Equal(ht, expected, lookedUp.machineRecorded)
	}, hegel.WithTestCases(1000))
}

func TestVectorHubLegacyCompatibilityRewritesCoverage(t *testing.T) {
	for _, witness := range []string{"unknown", "missing", "old version", "changed scope", "resumed full", "legacy machine"} {
		t.Run(witness, func(t *testing.T) {
			sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_upgrade_test")
			seedVectorSession(t, local, "A")
			first := hubRecipeSource("legacy-a", map[string]string{"max_input_chars": "8192"})
			first.hashes["A"] = "aggregate-a"
			first.docs["A"] = []storage.VectorPushDoc{vdoc("A", "o:A:0", 0, "old content", "old-hash", []float32{1, 0, 0, 0})}
			sync.vectorSource = first
			result, err := sync.Push(t.Context(), false, nil)
			require.NoError(t, err)
			generation := result.Vectors.GenerationID
			table := vectorChunkTable(generation)
			_, err = pg.ExecContext(t.Context(), "CREATE TABLE legacy_chunks AS SELECT * FROM "+table)
			require.NoError(t, err)
			_, err = pg.ExecContext(t.Context(), "CREATE TABLE legacy_state AS SELECT * FROM vector_push_state WHERE generation_id=$1", generation)
			require.NoError(t, err)
			second := hubRecipeSource("legacy-b", map[string]string{"max_input_chars": "8192"})
			second.hashes["A"] = "aggregate-b"
			second.docs["A"] = []storage.VectorPushDoc{vdoc("A", "o:A:0", 0, "new content", "new-hash", []float32{0, 1, 0, 0})}
			sync.vectorSource = second
			_, err = sync.Push(t.Context(), false, nil)
			require.NoError(t, err)
			// Older writers updated shared documents without retiring other generations'
			// chunks and delta hashes. Restore that reachable pre-upgrade database state.
			_, err = pg.ExecContext(t.Context(), "INSERT INTO "+table+" SELECT * FROM legacy_chunks")
			require.NoError(t, err)
			_, err = pg.ExecContext(t.Context(), "INSERT INTO vector_push_state SELECT * FROM legacy_state")
			require.NoError(t, err)
			switch witness {
			case "legacy machine":
				_, err = pg.ExecContext(t.Context(), "DELETE FROM vector_generation_machines WHERE generation_id=$1", generation)
				require.NoError(t, err)
				_, err = pg.ExecContext(t.Context(), `INSERT INTO vector_generation_machines
				(generation_id,machine,last_push_at) VALUES ($1,$2,now())`, generation, sync.machine)
			case "unknown":
				_, err = pg.ExecContext(t.Context(), "UPDATE vector_generation_machines SET data_version=NULL,include_automated=NULL WHERE generation_id=$1", generation)
			case "missing":
				_, err = pg.ExecContext(t.Context(), "DELETE FROM vector_generation_machines WHERE generation_id=$1", generation)
			case "changed scope":
				_, err = pg.ExecContext(t.Context(), "UPDATE vector_generation_machines SET include_automated=true WHERE generation_id=$1", generation)
			case "resumed full":
				_, err = pg.ExecContext(t.Context(), "UPDATE vector_generation_machines SET data_version=NULL,include_automated=NULL WHERE generation_id=$1", generation)
				sync.fullRun = &fullPushRunTracker{run: fullPushRun{VectorGeneration: generation, Vectors: map[string]string{"A": "aggregate-a"}}, lastSaved: time.Now(), interval: time.Hour}
			case "old version":
				_, err = pg.ExecContext(t.Context(), "UPDATE vector_generation_machines SET data_version=$2 WHERE generation_id=$1", generation, db.CurrentDataVersion()-1)
			}
			require.NoError(t, err)
			sync.vectorSource = first
			// A failed session must not be hidden by the legacy equal-hash skip.
			deferred, err := sync.pushVectors(t.Context(), witness == "resumed full", nil, 0, map[string]struct{}{"A": {}}, nil)
			require.NoError(t, err)
			assert.Equal(t, 1, deferred.SessionsDeferred)
			store := &Store{pg: pg}
			setHubTestSearcher(t, store, generation)
			pending, err := store.HubVectorGeneration(t.Context())
			require.NoError(t, err)
			assert.NotEmpty(t, pending.Unavailable)
			if witness == "legacy machine" {
				assert.Equal(t, 1, countRows(t, pg, "SELECT count(*) FROM vector_generation_machines WHERE generation_id=$1 AND machine=$2", generation, sync.machine), "deferred reconciliation retains the legacy witness")
			}
			blocked, lookupErr := store.LookupHubVectors(t.Context(), vector.HubLookupRequest{Fingerprint: "legacy-a", Identities: []vector.HubIdentity{{SessionID: "A", UnitKind: "user", ContentHash: "new-hash"}}})
			require.ErrorIs(t, lookupErr, vector.ErrHubGenerationChanged)
			assert.Empty(t, blocked.Chunks, "unverified legacy chunks cannot bypass discovery")
			result.Vectors, err = sync.pushVectors(t.Context(), witness == "resumed full", nil, 0, nil, nil)
			require.NoError(t, err)
			assert.Equal(t, 1, result.Vectors.SessionsPushed, "first certification repairs historical coverage even when its aggregate hash matches")
			recipe, err := store.HubVectorGeneration(t.Context())
			require.NoError(t, err)
			assert.Empty(t, recipe.Unavailable)
			identity := vector.HubIdentity{SessionID: "A", UnitKind: "user", ContentHash: "new-hash"}
			reply, err := store.LookupHubVectors(t.Context(), vector.HubLookupRequest{Fingerprint: "legacy-a", Identities: []vector.HubIdentity{identity}})
			require.NoError(t, err)
			assert.Empty(t, reply.Chunks, "old vectors must never be served under another generation's newer content hash")
			assert.Equal(t, []int{0}, reply.Absent)
			identity.ContentHash = "old-hash"
			reply, err = store.LookupHubVectors(t.Context(), vector.HubLookupRequest{Fingerprint: "legacy-a", Identities: []vector.HubIdentity{identity}})
			require.NoError(t, err)
			require.Len(t, reply.Chunks, 1)
			values, err := vector.DecodeHubVector(reply.Chunks[0].Vector, 4)
			require.NoError(t, err)
			assert.Equal(t, []float32{1, 0, 0, 0}, values)
			again, err := sync.pushVectors(t.Context(), false, nil, 0, nil, nil)
			require.NoError(t, err)
			assert.Equal(t, 1, again.SessionsUnchanged, "verified publishers retain ordinary delta skips")
			failed, err := sync.pushVectors(t.Context(), false, nil, 0, map[string]struct{}{"A": {}}, nil)
			require.NoError(t, err)
			assert.Equal(t, 1, failed.SessionsDeferred, "failed session writes cannot be hidden by verified delta skips")
		})
	}
}

func hubRecipeSource(fingerprint string, params map[string]string) *fakeVectorSource {
	source := recipeSource(fingerprint, params)
	value := false
	source.gen.IncludeAutomated = &value
	return source
}

func TestVectorHubScopedCompatibilityChangePromotesReconciliation(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_scope_test")
	seedVectorSession(t, local, "A")
	seedVectorSession(t, local, "B")
	source := hubRecipeSource("scope", map[string]string{"max_input_chars": "8192"})
	source.hashes["B"] = "b1"
	source.docs["B"] = []storage.VectorPushDoc{vdoc("B", "o:B:0", 0, "b1", "b1", []float32{1, 0, 0, 0})}
	sync.vectorSource = source
	_, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	automated := true
	source.gen.IncludeAutomated = &automated
	source.hashes["A"] = "a2"
	source.docs["A"][0].ContentHash = "a2"
	source.hashes["B"] = "b2"
	source.docs["B"][0].ContentHash = "b2"
	_, err = sync.pushVectors(t.Context(), false, []string{"A"}, 0, nil, nil)
	require.NoError(t, err)
	var scope bool
	require.NoError(t, pg.QueryRow(`SELECT include_automated FROM vector_generation_machines`).Scan(&scope))
	assert.True(t, scope)
	var hash string
	require.NoError(t, pg.QueryRow(`SELECT content_hash FROM vector_documents WHERE session_id='B'`).Scan(&hash))
	assert.Equal(t, "b2", hash, "scope change reconciles the whole corpus")
}

func TestVectorHubLegacyWitnessRetirement(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_alias_test")
	seedVectorSession(t, local, "A")
	source := hubRecipeSource("legacy-alias", map[string]string{"max_input_chars": "8192"})
	sync.vectorSource = source
	_, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	initialKey, err := sync.vectorGenerationWitnessKey(t.Context())
	require.NoError(t, err)
	suffix := strings.TrimPrefix(initialKey, sync.machine)
	generation, err := sync.resolveVectorGeneration(t.Context(), source.gen, initialKey)
	require.NoError(t, err)
	foreignGeneration, err := ensureVectorGeneration(t.Context(), pg, "foreign-alias", "m", 4)
	require.NoError(t, err)
	hegel.Test(t, func(ht *hegel.T) {
		current := fmt.Sprintf("current-%d", hegel.Draw(ht, hegel.Integers(math.MinInt32, math.MaxInt32)))
		previous := fmt.Sprintf("previous-λ|%d", hegel.Draw(ht, hegel.Integers(math.MinInt32, math.MaxInt32)))
		key := current + suffix
		unrelated := previous + "-other"
		otherScope := previous + suffix + "-other"
		before := []string{previous, current, previous + suffix, unrelated, otherScope}
		_, err := pg.ExecContext(ht.Context(), "DELETE FROM vector_generation_machines")
		require.NoError(ht, err)
		for _, name := range before {
			_, err = pg.ExecContext(ht.Context(), `INSERT INTO vector_generation_machines
			(generation_id,machine,last_push_at) VALUES ($1,$2,now())`, generation.id, name)
			require.NoError(ht, err)
		}
		_, err = pg.ExecContext(ht.Context(), `INSERT INTO vector_generation_machines
		(generation_id,machine,last_push_at) VALUES ($1,$2,now())`, foreignGeneration, previous)
		require.NoError(ht, err)
		ctx := ht.Context()
		canceled := hegel.Draw(ht, hegel.Booleans())
		if canceled {
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		ok, err := sync.recordVectorGenerationMachine(ctx, source.gen.Fingerprint, generation, key, source.gen.IncludeAutomated)
		want := []string{key, unrelated, otherScope}
		if canceled {
			require.Error(ht, err)
			require.False(ht, ok)
			want = before
		} else {
			require.NoError(ht, err)
			require.True(ht, ok)
			ok, err = sync.recordVectorGenerationMachine(ctx, source.gen.Fingerprint, generation, key, source.gen.IncludeAutomated)
			require.NoError(ht, err)
			require.True(ht, ok, "repeated certification is idempotent")
		}
		rows, err := pg.QueryContext(ht.Context(), "SELECT machine FROM vector_generation_machines WHERE generation_id=$1", generation.id)
		require.NoError(ht, err)
		defer rows.Close()
		var got []string
		for rows.Next() {
			var name string
			require.NoError(ht, rows.Scan(&name))
			got = append(got, name)
		}
		require.NoError(ht, rows.Err())
		require.ElementsMatch(ht, want, got)
		var foreignCount int
		require.NoError(ht, pg.QueryRowContext(ht.Context(), "SELECT count(*) FROM vector_generation_machines WHERE generation_id=$1 AND machine=$2", foreignGeneration, previous).Scan(&foreignCount))
		require.Equal(ht, 1, foreignCount, "another generation's plain witness remains untouched")
	}, hegel.WithTestCases(1000))
}

func TestVectorHubMachineRenameRetiresCompatibilityWitness(t *testing.T) {
	sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_rename_test")
	seedVectorSession(t, local, "A")
	source := hubRecipeSource("rename", map[string]string{"max_input_chars": "8192"})
	sync.vectorSource = source
	res, err := sync.Push(t.Context(), false, nil)
	require.NoError(t, err)
	store := &Store{pg: pg}
	setHubTestSearcher(t, store, res.Vectors.GenerationID)
	sync.machine = "renamed-machine"
	automated := true
	source.gen.IncludeAutomated = &automated
	_, err = sync.pushVectors(t.Context(), false, nil, 0, nil, nil)
	require.NoError(t, err)
	generation, err := store.HubVectorGeneration(t.Context())
	require.NoError(t, err)
	assert.Empty(t, generation.Unavailable)
	assert.True(t, generation.IncludeAutomated)
	assert.Equal(t, 1, countRows(t, pg, `SELECT count(*) FROM vector_generation_machines`))
}

func TestVectorHubIncompleteCompatibilityPushIsUnavailable(t *testing.T) {
	for _, first := range []bool{false, true} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("first=%t/canceled=%t", first, canceled), func(t *testing.T) {
				sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_partial_test")
				seedVectorSession(t, local, "A")
				seedVectorSession(t, local, "B")
				source := hubRecipeSource("partial", map[string]string{"max_input_chars": "8192"})
				source.hashes["B"] = "b1"
				source.docs["B"] = []storage.VectorPushDoc{vdoc("B", "o:B:0", 0, "b1", "b1", []float32{1, 0, 0, 0})}
				sync.vectorSource = source
				res, err := sync.Push(t.Context(), false, nil)
				require.NoError(t, err)
				store := &Store{pg: pg}
				setHubTestSearcher(t, store, res.Vectors.GenerationID)
				if first {
					_, err = pg.Exec(`UPDATE vector_generation_machines SET machine='other-pusher'`)
					require.NoError(t, err)
				}
				automated := true
				source.gen.IncludeAutomated = &automated
				for _, id := range []string{"A", "B"} {
					source.hashes[id] = id + "2"
					source.docs[id][0].ContentHash = id + "2"
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var observed bool
				progress := func(p storage.PushProgress) {
					if p.VectorChunksPushed == 0 {
						return
					}
					observed = true
					generation, err := store.HubVectorGeneration(t.Context())
					require.NoError(t, err)
					assert.NotEmpty(t, generation.Unavailable, "committed chunks must not retain old compatibility")
					if canceled {
						cancel()
					}
				}
				var failed map[string]struct{}
				if !canceled {
					failed = map[string]struct{}{"B": {}}
				}
				res.Vectors, err = sync.pushVectors(ctx, false, nil, 0, failed, progress)
				if canceled {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					require.NoError(t, err)
					assert.Equal(t, 1, res.Vectors.SessionsDeferred)
				}
				require.True(t, observed)
				generation, err := store.HubVectorGeneration(t.Context())
				require.NoError(t, err)
				assert.NotEmpty(t, generation.Unavailable, "incomplete pushes must remain unavailable")
			})
		}
	}
}

func setHubTestSearcher(t *testing.T, store *Store, generationID int64) {
	t.Helper()
	var fingerprint string
	require.NoError(t, store.pg.QueryRow(`SELECT fingerprint FROM vector_generations WHERE id=$1`, generationID).Scan(&fingerprint))
	searcher, reason, err := (Backend{}).OpenVectorSearcher(t.Context(), store, storage.VectorGenerationInfo{Fingerprint: fingerprint}, 8192, nil)
	require.NoError(t, err)
	require.Empty(t, reason)
	require.NotNil(t, searcher)
	store.SetVectorSearcher(searcher)
}

func TestVectorHubRejectsRecreatedSelectedGeneration(t *testing.T) {
	for _, tc := range []struct {
		name, fingerprint string
		dimension         int
	}{
		{"same recipe", "selected", 4},
		{"changed recipe", "replacement", 4},
		{"changed dimension", "replacement", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_recreated_test")
			seedVectorSession(t, local, "A")
			source := hubRecipeSource("selected", map[string]string{"max_input_chars": "8192"})
			source.docs["A"] = []storage.VectorPushDoc{vdoc("A", "o:A:0", 0, "content", "hash", []float32{1, 0, 0, 0})}
			sync.vectorSource = source
			res, err := sync.Push(t.Context(), false, nil)
			require.NoError(t, err)
			store := &Store{pg: pg}
			setHubTestSearcher(t, store, res.Vectors.GenerationID)
			var before string
			require.NoError(t, pg.QueryRow(`SELECT created_at::text FROM vector_generations WHERE id=$1`, res.Vectors.GenerationID).Scan(&before))
			// Recreate before the first discovery call: pinning cannot be lazy.
			for _, table := range []string{vectorChunkTable(res.Vectors.GenerationID), "vector_push_state", "vector_generation_machines", "vector_documents", "vector_generations"} {
				_, err = pg.Exec(`DROP TABLE ` + table)
				require.NoError(t, err)
			}
			source.gen.Fingerprint = tc.fingerprint
			source.gen.Dimension = tc.dimension
			source.docs["A"][0].Chunks[0].Embedding = make([]float32, tc.dimension)
			source.docs["A"][0].Chunks[0].Embedding[0] = 1
			pushed, err := sync.pushVectors(t.Context(), false, nil, 0, nil, nil)
			require.NoError(t, err)
			require.Equal(t, res.Vectors.GenerationID, pushed.GenerationID, "table recreation reuses the selected ID")
			var after string
			require.NoError(t, pg.QueryRow(`SELECT created_at::text FROM vector_generations WHERE id=$1`, pushed.GenerationID).Scan(&after))
			require.NotEqual(t, before, after)
			generation, err := store.HubVectorGeneration(t.Context())
			require.NoError(t, err)
			assert.NotEmpty(t, generation.Unavailable)
			for _, fingerprint := range []string{"selected", tc.fingerprint} {
				_, err = store.LookupHubVectors(t.Context(), vector.HubLookupRequest{Fingerprint: fingerprint, Identities: []vector.HubIdentity{{SessionID: "A", UnitKind: "user", Ordinal: 0, ContentHash: "hash"}}})
				assert.ErrorIs(t, err, vector.ErrHubGenerationChanged)
			}
		})
	}
}

func TestVectorHubRejectsMissingSelectedChunks(t *testing.T) {
	for _, discovered := range []bool{false, true} {
		t.Run(fmt.Sprintf("discovered=%t", discovered), func(t *testing.T) {
			sync, local, pg := newVectorPushTestSync(t, testPGURL(t), "agentsview_vector_hub_missing_chunks_test")
			seedVectorSession(t, local, "A")
			source := hubRecipeSource("selected", map[string]string{"max_input_chars": "8192"})
			source.docs["A"] = []storage.VectorPushDoc{vdoc("A", "o:A:0", 0, "content", "hash", []float32{1, 0, 0, 0})}
			sync.vectorSource = source
			res, err := sync.Push(t.Context(), false, nil)
			require.NoError(t, err)
			store := &Store{pg: pg}
			setHubTestSearcher(t, store, res.Vectors.GenerationID)
			if discovered {
				generation, err := store.HubVectorGeneration(t.Context())
				require.NoError(t, err)
				require.Empty(t, generation.Unavailable)
			}
			_, err = pg.Exec(`DROP TABLE ` + vectorChunkTable(res.Vectors.GenerationID))
			require.NoError(t, err)
			generation, err := store.HubVectorGeneration(t.Context())
			require.NoError(t, err)
			assert.NotEmpty(t, generation.Unavailable)
			_, err = store.LookupHubVectors(t.Context(), vector.HubLookupRequest{Fingerprint: "selected", Identities: []vector.HubIdentity{{SessionID: "A", UnitKind: "user", Ordinal: 0, ContentHash: "hash"}}})
			assert.ErrorIs(t, err, vector.ErrHubGenerationChanged)
		})
	}
}
