// SPDX-FileCopyrightText: 2022 Free Mobile
// SPDX-License-Identifier: AGPL-3.0-only

package core

import (
	"testing"

	"akvorado/common/helpers"
)

func TestDefaultConfiguration(t *testing.T) {
	if err := helpers.Validate.Struct(DefaultConfiguration()); err != nil {
		t.Fatalf("validate.Struct() error:\n%+v", err)
	}
}

func TestConfigurationUnmarshallerHook(t *testing.T) {
	helpers.TestConfigurationDecode(t, helpers.ConfigurationDecodeCases{
		{
			Description:    "nil",
			Initial:        func() any { return Configuration{} },
			Configuration:  func() any { return nil },
			Expected:       Configuration{},
			SkipValidation: true,
		}, {
			Description:    "empty",
			Initial:        func() any { return Configuration{} },
			Configuration:  func() any { return helpers.M{} },
			Expected:       Configuration{},
			SkipValidation: true,
		}, {
			Description: "ignore-asn-from-flow = false",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"ignore-asn-from-flow": false,
				}
			},
			Expected:       Configuration{},
			SkipValidation: true,
		}, {
			Description: "ignore-asn-from-flow = true",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"ignore-asn-from-flow": true,
				}
			},
			Expected: Configuration{
				ASNProviders: []ASNProvider{ASNProviderRouting, ASNProviderGeoIP},
			},
			SkipValidation: true,
		}, {
			Description: "ignore-asn-from-flow and asn-providers",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"ignore-asn-from-flow": true,
					"asn-providers":        []string{"routing", "flow"},
				}
			},
			Error:          true,
			SkipValidation: true,
		}, {
			Description: "asn-providers only",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"asn-providers": []string{"flow-except-private", "routing", "flow"},
				}
			},
			Expected: Configuration{
				ASNProviders: []ASNProvider{ASNProviderFlowExceptPrivate, ASNProviderRouting, ASNProviderFlow},
			},
			SkipValidation: true,
		}, {
			Description: "net-providers with bmp",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"net-providers": []string{"flow", "bmp"},
				}
			},
			Expected: Configuration{
				NetProviders: []NetProvider{NetProviderFlow, NetProviderRouting},
			},
			SkipValidation: true,
		}, {
			Description: "asn-providers with bmp",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"asn-providers": []string{"flow", "bmp", "bmp-except-private"},
				}
			},
			Expected: Configuration{
				ASNProviders: []ASNProvider{ASNProviderFlow, ASNProviderRouting, ASNProviderRoutingExceptPrivate},
			},
			SkipValidation: true,
		}, {
			Description: "net-providers",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"net-providers": []string{"flow", "routing"},
				}
			},
			Expected: Configuration{
				NetProviders: []NetProvider{NetProviderFlow, NetProviderRouting},
			},
			SkipValidation: true,
		}, {
			Description: "anonymize scope all",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"anonymize": helpers.M{
						"enabled": true,
						"scope":   "all",
					},
				}
			},
			Expected: Configuration{
				Anonymize: AnonymizeConfig{
					Enabled:   true,
					Scope:     AnonymizeScopeAll,
				},
			},
			SkipValidation: true,
		}, {
			Description: "anonymize scope external-boundary",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"anonymize": helpers.M{
						"enabled": true,
						"scope":   "external-boundary",
					},
				}
			},
			Expected: Configuration{
				Anonymize: AnonymizeConfig{
					Enabled:   true,
					Scope:     AnonymizeScopeExternalBoundary,
				},
			},
			SkipValidation: true,
		}, {
			Description: "anonymize scope as-list",
			Initial:     func() any { return Configuration{} },
			Configuration: func() any {
				return helpers.M{
					"anonymize": helpers.M{
						"enabled":    true,
						"scope":      "as-list",
						"scope-asns": []uint32{65001, 65002, 65003},
					},
				}
			},
			Expected: Configuration{
				Anonymize: AnonymizeConfig{
					Enabled:   true,
					Scope:     AnonymizeScopeASList,
					ScopeASNs: []uint32{65001, 65002, 65003},
				},
			},
			SkipValidation: true,
		},
	})
}
