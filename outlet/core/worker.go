// SPDX-FileCopyrightText: 2025 Free Mobile
// SPDX-License-Identifier: AGPL-3.0-only

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"akvorado/common/pb"
	"akvorado/common/reporter"
	"akvorado/common/schema"
	"akvorado/outlet/clickhouse"
	"akvorado/outlet/kafka"
)

// worker represents a worker processing incoming flows.
type worker struct {
	c       *Component
	l       reporter.Logger
	cw      clickhouse.Worker
	bf      *schema.FlowMessage
	rawFlow pb.RawFlow

	scaleRequestChan chan<- kafka.ScaleRequest
}

// newWorker instantiates a new worker and returns a callback function to
// process an incoming flow and a function to call on shutdown.
func (c *Component) newWorker(i int, scaleRequestChan chan<- kafka.ScaleRequest) (kafka.ReceiveFunc, kafka.ShutdownFunc) {
	bf := c.d.Schema.NewFlowMessage()
	w := worker{
		c:                c,
		l:                c.r.With().Int("worker", i).Logger(),
		bf:               bf,
		cw:               c.d.ClickHouse.NewWorker(i, bf),
		scaleRequestChan: scaleRequestChan,
	}
	return w.processIncomingFlow, w.shutdown
}

// shutdown shutdowns the worker, flushing any remaining data.
func (w *worker) shutdown() {
	w.l.Info().Msg("flush final batch to ClickHouse")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	w.cw.Flush(ctx)
	w.l.Info().Msg("worker stopped")
}

// processIncomingFlow processes one incoming flow from Kafka.
func (w *worker) processIncomingFlow(ctx context.Context, data []byte) error {
	// Raw flow decoding
	w.c.metrics.rawFlowsReceived.Inc()
	w.rawFlow.ResetVT()
	if err := w.rawFlow.UnmarshalVT(data); err != nil {
		w.c.metrics.rawFlowsErrors.WithLabelValues("cannot decode protobuf")
		return fmt.Errorf("cannot decode raw flow: %w", err)
	}

	// Process each decoded flow
	finalize := func() {
		// Accounting
		exporter := w.bf.ExporterAddress.Unmap().String()
		w.c.metrics.flowsReceived.WithLabelValues(exporter).Inc()

		// Enrichment
		ip := w.bf.ExporterAddress
		skip, inIfBoundary, outIfBoundary := w.enrichFlow(ip, exporter)
		if skip {
			w.bf.Undo()
			return
		}

		// anonymize IPs stored in the flow message before ClickHouse insert
		if w.c.anonymizer != nil && w.c.anonymizer.enabled {
			if w.shouldAnonymize(w.bf.SrcAddr, w.bf.SrcAS, inIfBoundary, true) {
				w.bf.SrcAddr = w.anonymizeAddr(w.bf.SrcAddr)
			}
			if w.shouldAnonymize(w.bf.DstAddr, w.bf.DstAS, outIfBoundary, false) {
				w.bf.DstAddr = w.anonymizeAddr(w.bf.DstAddr)
			}
		}

		// If we have HTTP clients, send to them too
		if atomic.LoadUint32(&w.c.httpFlowClients) > 0 {
			if jsonBytes, err := json.Marshal(w.bf); err == nil {
				select {
				case w.c.httpFlowChannel <- jsonBytes: // OK
				default: // Overflow, best effort and ignore
				}
			}
		}

		// Finalize and forward to ClickHouse
		w.c.metrics.flowsForwarded.WithLabelValues(exporter).Inc()
		status := w.cw.FinalizeAndSend(ctx)
		switch status {
		case clickhouse.WorkerStatusOverloaded:
			w.scaleRequestChan <- kafka.ScaleIncrease
		case clickhouse.WorkerStatusUnderloaded:
			w.scaleRequestChan <- kafka.ScaleDecrease
		case clickhouse.WorkerStatusSteady:
			w.scaleRequestChan <- kafka.ScaleSteady
		}
	}

	// Flow decoding
	err := w.c.d.Flow.Decode(&w.rawFlow, w.bf, finalize)
	if err != nil {
		// w.bf.ExporterAddress may not be known yet, so increase raw_flows_errors_total.
		w.c.metrics.rawFlowsErrors.WithLabelValues("cannot decode payload").Inc()
		return nil
	}

	return nil
}

// shouldAnonymize determines whether an IP address should be anonymized based on the configured scope.
// It takes the AS number and interface boundary for the address being checked.
// isSrc indicates whether this is a source address (true) or destination address (false).
func (w *worker) shouldAnonymize(addr netip.Addr, asn uint32, boundary schema.InterfaceBoundary, isSrc bool) bool {
	if !addr.IsValid() {
		return false
	}

	switch w.c.anonymizer.scope {
	case AnonymizeScopeAll:
		// Anonymize everything (default behavior)
		return true

	case AnonymizeScopeExternalBoundary:
		// Only anonymize if the interface boundary is external
		return boundary == schema.InterfaceBoundaryExternal

	case AnonymizeScopeASList:
		// Only anonymize if the AS number is in the configured list
		if len(w.c.anonymizer.scopeASNs) == 0 {
			// If no ASNs configured, don't anonymize anything
			return false
		}
		// ASN 0 indicates unknown/unassigned AS, don't anonymize
		if asn == 0 {
			return false
		}
		return w.c.anonymizer.scopeASNs[asn]

	default:
		// Unknown scope, default to anonymizing everything for safety
		w.l.Warn().Str("scope", string(w.c.anonymizer.scope)).Msg("unknown anonymization scope, defaulting to anonymize all")
		return true
	}
}

// anonymizeAddr converts netip.Addr -> net.IP, applies either aggregation or cryptopan
// depending on the configured mode, and returns a new netip.Addr. On error it returns
// the original address unchanged.
func (w *worker) anonymizeAddr(a netip.Addr) netip.Addr {
	if !a.IsValid() {
		return a
	}
	ip := net.ParseIP(a.String())
	if ip == nil {
		return a
	}

	var out net.IP
	if w.c.anonymizer.aggregate {
		out = w.c.anonymizer.AggregateIP(ip)
	} else {
		out = w.c.anonymizer.AnonymizeIP(ip)
	}
	if out == nil {
		return a
	}
	if na, err := netip.ParseAddr(out.String()); err == nil {
		return na
	}
	return a
}
