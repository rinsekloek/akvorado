// SPDX-FileCopyrightText: 2025 Free Mobile
// SPDX-License-Identifier: AGPL-3.0-only

package core

import (
	"net/netip"
	"testing"

	"akvorado/common/schema"
)

func TestAnonymizationScope(t *testing.T) {
	tests := []struct {
		name          string
		scope         AnonymizeScope
		inBoundary    schema.InterfaceBoundary
		outBoundary   schema.InterfaceBoundary
		srcAS         uint32
		dstAS         uint32
		isSrc         bool
		shouldAnon    bool
	}{
		{
			name:       "always scope - should anonymize",
			scope:      AnonymizeScopeAlways,
			inBoundary: schema.InterfaceBoundaryUndefined,
			shouldAnon: true,
		},
		{
			name:       "external scope with external inbound - should anonymize",
			scope:      AnonymizeScopeExternal,
			inBoundary: schema.InterfaceBoundaryExternal,
			shouldAnon: true,
		},
		{
			name:        "external scope with external outbound - should anonymize",
			scope:       AnonymizeScopeExternal,
			outBoundary: schema.InterfaceBoundaryExternal,
			shouldAnon:  true,
		},
		{
			name:       "external scope with internal only - should not anonymize",
			scope:      AnonymizeScopeExternal,
			inBoundary: schema.InterfaceBoundaryInternal,
			shouldAnon: false,
		},
		{
			name:       "internal scope with internal inbound - should anonymize",
			scope:      AnonymizeScopeInternal,
			inBoundary: schema.InterfaceBoundaryInternal,
			shouldAnon: true,
		},
		{
			name:        "internal scope with internal outbound - should anonymize",
			scope:       AnonymizeScopeInternal,
			outBoundary: schema.InterfaceBoundaryInternal,
			shouldAnon:  true,
		},
		{
			name:       "internal scope with external only - should not anonymize",
			scope:      AnonymizeScopeInternal,
			inBoundary: schema.InterfaceBoundaryExternal,
			shouldAnon: false,
		},
		{
			name:       "public-as scope with public AS (src) - should anonymize",
			scope:      AnonymizeScopePublicAS,
			srcAS:      174, // public AS (Cogent)
			isSrc:      true,
			shouldAnon: true,
		},
		{
			name:       "public-as scope with private AS (src) - should not anonymize",
			scope:      AnonymizeScopePublicAS,
			srcAS:      64500, // private AS range
			isSrc:      true,
			shouldAnon: false,
		},
		{
			name:       "public-as scope with public AS (dst) - should anonymize",
			scope:      AnonymizeScopePublicAS,
			dstAS:      174, // public AS (Cogent)
			isSrc:      false,
			shouldAnon: true,
		},
		{
			name:       "public-as scope with private AS (dst) - should not anonymize",
			scope:      AnonymizeScopePublicAS,
			dstAS:      64500, // private AS range
			isSrc:      false,
			shouldAnon: false,
		},
		{
			name:       "private-as scope with private AS (src) - should anonymize",
			scope:      AnonymizeScopePrivateAS,
			srcAS:      64500, // private AS range
			isSrc:      true,
			shouldAnon: true,
		},
		{
			name:       "private-as scope with public AS (src) - should not anonymize",
			scope:      AnonymizeScopePrivateAS,
			srcAS:      174, // public AS (Cogent)
			isSrc:      true,
			shouldAnon: false,
		},
		{
			name:       "private-as scope with private AS (dst) - should anonymize",
			scope:      AnonymizeScopePrivateAS,
			dstAS:      64500, // private AS range
			isSrc:      false,
			shouldAnon: true,
		},
		{
			name:       "private-as scope with public AS (dst) - should not anonymize",
			scope:      AnonymizeScopePrivateAS,
			dstAS:      174, // public AS (Cogent)
			isSrc:      false,
			shouldAnon: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock worker with test configuration
			w := &worker{
				c: &Component{
					config: Configuration{
						Anonymize: AnonymizeConfig{
							Scope: tt.scope,
						},
					},
				},
				bf: &schema.FlowMessage{
					SrcAS: tt.srcAS,
					DstAS: tt.dstAS,
				},
				inIfBoundary:  tt.inBoundary,
				outIfBoundary: tt.outBoundary,
			}

			addr := netip.MustParseAddr("192.0.2.1")
			got := w.shouldAnonymize(addr, tt.isSrc)
			if got != tt.shouldAnon {
				t.Errorf("shouldAnonymize() = %v, want %v", got, tt.shouldAnon)
			}
		})
	}
}

func TestAnonymizationScopeInvalidAddress(t *testing.T) {
	w := &worker{
		c: &Component{
			config: Configuration{
				Anonymize: AnonymizeConfig{
					Scope: AnonymizeScopeAlways,
				},
			},
		},
		bf: &schema.FlowMessage{},
	}

	// Invalid address should not be anonymized
	invalidAddr := netip.Addr{}
	if w.shouldAnonymize(invalidAddr, true) {
		t.Error("shouldAnonymize() with invalid address should return false")
	}
}
