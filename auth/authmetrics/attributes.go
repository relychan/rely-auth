// Copyright 2026 RelyChan Pte. Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authmetrics

import (
	"github.com/relychan/rely-auth/auth/authmode"
	"go.opentelemetry.io/otel/attribute"
)

var (
	// AuthStatusSuccessAttribute is the constant attribute for the success auth status.
	AuthStatusSuccessAttribute = attribute.String("auth.status", "success")
	// AuthStatusFailedAttribute is the constant attribute for the failed auth status.
	AuthStatusFailedAttribute = attribute.String("auth.status", "failed")
)

// NewAuthModeAttribute creates an auth.mode attribute.
func NewAuthModeAttribute(authMode authmode.AuthMode) attribute.KeyValue {
	return attribute.String("auth.mode", string(authMode))
}

// NewAuthIDAttribute creates an auth.id attribute.
func NewAuthIDAttribute(id string) attribute.KeyValue {
	return attribute.String("auth.id", id)
}
