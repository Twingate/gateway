// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package config

// Keys used in HTTP header templates.
const (
	JWT              = "jwt"
	Username         = "username"
	Groups           = "groups"
	ClientGeoLatLong = "clientGeoLatLong"
	ClientCity       = "clientCity"
	ClientRegion     = "clientRegion"
	ClientCountry    = "clientCountry"
)

var allowedWebAppKeys = []string{
	JWT,
	Username,
	Groups,
	ClientGeoLatLong,
	ClientCity,
	ClientRegion,
	ClientCountry,
}
