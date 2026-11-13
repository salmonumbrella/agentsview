package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.kenn.io/agentsview/internal/export"
)

func identityObs(
	root, remote, remoteName string,
) export.ProjectIdentityObservation {
	return export.ProjectIdentityObservation{
		Project:       "proj",
		Machine:       "m1",
		RootPath:      root,
		GitRemote:     remote,
		GitRemoteName: remoteName,
		ObservedAt:    time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestPlanProjectIdentityObservationSync(t *testing.T) {
	tests := []struct {
		name          string
		observations  []export.ProjectIdentityObservation
		wantReal      []string // GitRemoteName markers, in order
		wantAmbiguous []string // RootPath markers, in order
		wantFallbacks []string // RootPath markers, in order
		wantRoots     []string // RootPath markers, in order
	}{
		{
			name: "real shadows fallback regardless of order",
			observations: []export.ProjectIdentityObservation{
				identityObs("/a", "", ""),
				identityObs("/a", "git@x:a.git", "origin"),
				identityObs("/b", "git@x:b.git", "origin"),
				identityObs("/b", "", ""),
			},
			wantReal:  []string{"origin", "origin"},
			wantRoots: []string{"/a", "/b"},
		},
		{
			name: "ambiguous survives alongside real remote",
			observations: func() []export.ProjectIdentityObservation {
				ambiguous := identityObs("/a", "", "")
				ambiguous.RemoteResolution = export.ProjectResolutionAmbiguous
				ambiguous.RemoteCandidateCount = 2
				return []export.ProjectIdentityObservation{
					identityObs("/a", "git@x:a.git", "origin"),
					ambiguous,
				}
			}(),
			wantReal:      []string{"origin"},
			wantAmbiguous: []string{"/a"},
			wantRoots:     []string{"/a"},
		},
		{
			name: "ambiguous wins over later unknown fallback",
			observations: func() []export.ProjectIdentityObservation {
				ambiguous := identityObs("/a", "", "")
				ambiguous.RemoteResolution = export.ProjectResolutionAmbiguous
				ambiguous.RemoteCandidateCount = 2
				unknown := identityObs("/a", "", "")
				unknown.RemoteResolution = export.ProjectResolutionUnknown
				return []export.ProjectIdentityObservation{ambiguous, unknown}
			}(),
			wantAmbiguous: []string{"/a"},
		},
		{
			name: "fallback without real survives to the pg check",
			observations: []export.ProjectIdentityObservation{
				identityObs("/a", "", ""),
				identityObs("/b", "git@x:b.git", "origin"),
			},
			wantReal:      []string{"origin"},
			wantFallbacks: []string{"/a"},
			wantRoots:     []string{"/b"},
		},
		{
			name: "last observation per conflict key wins",
			observations: []export.ProjectIdentityObservation{
				identityObs("/a", "git@x:a.git", "old"),
				identityObs("/a", "git@x:a.git", "new"),
				identityObs("/a", "git@y:a.git", "other"),
			},
			wantReal:  []string{"new", "other"},
			wantRoots: []string{"/a"},
		},
		{
			name: "empty input plans nothing",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := PlanProjectIdentityObservationSync(tt.observations)

			var gotReal []string
			for _, obs := range plan.RealRemote {
				gotReal = append(gotReal, obs.GitRemoteName)
			}
			assert.Equal(t, tt.wantReal, gotReal, "real remote observations")

			var gotAmbiguous []string
			for _, obs := range plan.Ambiguous {
				gotAmbiguous = append(gotAmbiguous, obs.RootPath)
			}
			assert.Equal(t, tt.wantAmbiguous, gotAmbiguous, "ambiguous observations")

			var gotFallbacks []string
			for _, obs := range plan.Fallbacks {
				gotFallbacks = append(gotFallbacks, obs.RootPath)
			}
			assert.Equal(t, tt.wantFallbacks, gotFallbacks, "fallbacks")

			var gotRoots []string
			for _, root := range plan.RealRoots {
				gotRoots = append(gotRoots, root.RootPath)
			}
			assert.Equal(t, tt.wantRoots, gotRoots, "real roots")
		})
	}
}

func TestCanonicalPushScope(t *testing.T) {
	for _, scope := range []struct {
		name                                                     string
		projects, excluded, reorderedProjects, reorderedExcluded []string
	}{
		{name: "nil"},
		{name: "empty", projects: []string{}, excluded: []string{}},
		{name: "included and excluded", projects: []string{"b", "a"}, excluded: []string{"y", "x"}, reorderedProjects: []string{"a", "b"}, reorderedExcluded: []string{"x", "y"}},
		{name: "included only", projects: []string{"b", "a"}, reorderedProjects: []string{"a", "b"}},
	} {
		t.Run(scope.name, func(t *testing.T) {
			got := CanonicalPushScope(scope.projects, scope.excluded)
			assert.Equal(t, got, CanonicalPushScope(scope.reorderedProjects, scope.reorderedExcluded))
			if len(scope.projects)+len(scope.excluded) == 0 {
				assert.Empty(t, got)
			} else {
				assert.NotEmpty(t, got)
			}
		})
	}
	assert.NotEqual(t, CanonicalPushScope([]string{"a"}, nil), CanonicalPushScope([]string{"a", "b"}, nil))
	assert.NotEqual(t, CanonicalPushScope([]string{"a"}, nil), CanonicalPushScope(nil, []string{"a"}))
}

func TestIdentitySelectedByRemotes(t *testing.T) {
	base := export.ProjectIdentityObservation{
		RemoteResolution: export.ProjectResolutionResolved,
		KeySource:        export.ProjectIdentityKeySourceGitRemote,
		NormalizedRemote: "github.com/org/repo",
	}
	cases := []struct {
		name string
		item export.ProjectIdentityObservation
		want bool
	}{
		{"selected", base, true},
		{"one candidate", export.ProjectIdentityObservation{RemoteResolution: base.RemoteResolution, KeySource: base.KeySource, NormalizedRemote: base.NormalizedRemote, RemoteCandidateCount: 1}, true},
		{"two candidates", export.ProjectIdentityObservation{RemoteResolution: base.RemoteResolution, KeySource: base.KeySource, NormalizedRemote: base.NormalizedRemote, RemoteCandidateCount: 2}, false},
		{"ambiguous", export.ProjectIdentityObservation{RemoteResolution: export.ProjectResolutionAmbiguous, KeySource: base.KeySource, NormalizedRemote: base.NormalizedRemote}, false},
		{"unknown", export.ProjectIdentityObservation{RemoteResolution: export.ProjectResolutionUnknown, KeySource: base.KeySource, NormalizedRemote: base.NormalizedRemote}, false},
		{"root path", export.ProjectIdentityObservation{RemoteResolution: base.RemoteResolution, KeySource: export.ProjectIdentityKeySourceRootPath, NormalizedRemote: base.NormalizedRemote}, false},
		{"other remote", export.ProjectIdentityObservation{RemoteResolution: base.RemoteResolution, KeySource: base.KeySource, NormalizedRemote: "github.com/org/other"}, false},
		{"missing remote", export.ProjectIdentityObservation{RemoteResolution: base.RemoteResolution, KeySource: base.KeySource}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IdentitySelectedByRemotes(tc.item, []string{"github.com/org/repo"}))
		})
	}
	items := []export.ProjectIdentityObservation{base, cases[3].item, cases[6].item}
	assert.Equal(t, []export.ProjectIdentityObservation{base}, FilterIdentityByRemotes(items, []string{"github.com/org/repo"}))
}
