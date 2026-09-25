/******************************************************************************
 * Copyright (c) 2026 Tenebris Technologies Inc.                              *
 * Please see LICENSE file for details.                                       *
 ******************************************************************************/

package alerter

import "context"

// Nop is an Alerter that discards everything. It is for tests and for hosts
// that run without alerting, so callers never have to check for nil.
type Nop struct{}

// Send discards the alert.
func (Nop) Send(Alert) {}

// Normal discards the alert.
func (Nop) Normal(string, string, ...string) {}

// Priority discards the alert.
func (Nop) Priority(string, string, ...string) {}

// Emergency discards the alert.
func (Nop) Emergency(string, string, ...string) {}

// Close does nothing.
func (Nop) Close(context.Context) error { return nil }
