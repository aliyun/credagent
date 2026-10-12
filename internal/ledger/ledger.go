// internal/ledger/ledger.go (v2.0 - REFACTORED FOR ATOMICITY)

package ledger

import (
	"fmt"
	"sync"
	"time"

	"github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/pkg/logger"
	"google.golang.org/protobuf/proto"
)

// ConsumeResult encapsulates the outcome of a ConsumeTicket operation.
type ConsumeResult struct {
	Success      bool
	DenialReason string
}

// LedgerStore defines a simplified, atomic interface for the release ledger.
type LedgerStore interface {
	// AddTicket adds a new permit ticket to the ledger.
	AddTicket(ticket *enclave.PermitTicket) error

	// ConsumeTicket atomically checks and consumes a ticket based on the given context.
	// This is the primary method for ticket verification. It handles all state transitions internally.
	ConsumeTicket(uuid string, pid int32, strategy string) ConsumeResult

	// GetTicket retrieves a ticket by its UUID without consuming it.
	// This is used for command spec verification.
	GetTicket(uuid string) (*enclave.PermitTicket, bool)

	// ListTickets returns all tickets in the ledger.
	ListTickets() []*enclave.PermitTicket

	// CleanupExpired removes expired tickets from the ledger. This can be run periodically.
	CleanupExpired()
}

// InMemoryLedger implements LedgerStore using an in-memory map with a single global lock.
// NOTE: The per-key lock idea is complex to implement correctly and is overkill for this stage.
// A single, well-managed global lock is safer and sufficient for now.
type InMemoryLedger struct {
	tickets map[string]*enclave.PermitTicket
	mu      sync.Mutex // Use a standard Mutex as we are always writing state.
}

// NewInMemoryLedger creates a new in-memory ledger.
func NewInMemoryLedger() *InMemoryLedger {
	ledger := &InMemoryLedger{
		tickets: make(map[string]*enclave.PermitTicket),
	}
	// Start a background goroutine to periodically clean up expired tickets.
	go ledger.startCleanupRoutine(10 * time.Minute)
	return ledger
}

// AddTicket adds a new permit ticket to the ledger.
func (l *InMemoryLedger) AddTicket(ticket *enclave.PermitTicket) error {
	if ticket == nil || ticket.GetUuid() == "" {
		return fmt.Errorf("invalid ticket: cannot be nil or have an empty UUID")
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Store a deep copy to prevent any external modifications.
	cloned := proto.Clone(ticket).(*enclave.PermitTicket)
	l.tickets[ticket.GetUuid()] = cloned
	return nil
}

// ConsumeTicket is the core atomic operation for ticket verification and consumption.
func (l *InMemoryLedger) ConsumeTicket(uuid string, pid int32, strategy string) ConsumeResult {
	l.mu.Lock()
	defer l.mu.Unlock()

	ticket, exists := l.tickets[uuid]
	if !exists {
		return ConsumeResult{Success: false, DenialReason: "Invalid UUID."}
	}

	// Check for expired or already burned tickets first.
	if ticket.GetStatus() == "BURNED" {
		return ConsumeResult{Success: false, DenialReason: "Ticket has already been used."}
	}
	if ticket.GetExpiresAt() != nil && ticket.GetExpiresAt().AsTime().Before(time.Now()) {
		// Lazily remove the expired ticket.
		delete(l.tickets, uuid)
		return ConsumeResult{Success: false, DenialReason: "Ticket has expired."}
	}

	// --- Main State Machine Logic ---
	switch strategy {
	case "ONE_TIME_USE":
		if ticket.GetStatus() != "PENDING" {
			return ConsumeResult{Success: false, DenialReason: "One-time ticket is not in PENDING state."}
		}
		// Atomically consume by marking as BURNED.
		ticket.Status = "BURNED"
		return ConsumeResult{Success: true}

	case "PID_BIND":
		if ticket.GetStatus() == "PENDING" {
			if int32(ticket.GetBoundPid()) == pid {
				logger.Debug("PID %d matches ticket %s in PENDING state, allowing rapid access for performance", pid, uuid)
				return ConsumeResult{Success: true}
			}
		}
		if ticket.GetStatus() == "ACTIVE" {
			if int32(ticket.GetBoundPid()) == pid {
				// Subsequent use by the same PID is allowed.
				return ConsumeResult{Success: true}
			} else {
				// Hijacking detected! Burn the ticket immediately.
				ticket.Status = "BURNED"
				reason := fmt.Sprintf("PID hijacking detected! Expected PID %d, got %d. Ticket burned.", int32(ticket.GetBoundPid()), pid)
				return ConsumeResult{Success: false, DenialReason: reason}
			}
		}
		// If ticket is not PENDING or ACTIVE, it's an invalid state for PID_BIND.
		return ConsumeResult{Success: false, DenialReason: fmt.Sprintf("Invalid ticket state '%s' for PID_BIND strategy.", ticket.GetStatus())}

	case "SPEC_VERIFICATION":
		// SPEC_VERIFICATION is handled separately in the engine, not in the ledger
		return ConsumeResult{Success: false, DenialReason: fmt.Sprintf("SPEC_VERIFICATION strategy should not be handled in ledger directly.")}

	default:
		return ConsumeResult{Success: false, DenialReason: fmt.Sprintf("Unknown strategy '%s' provided to ledger.", strategy)}
	}
}

// CleanupExpired removes expired tickets from the ledger.
func (l *InMemoryLedger) CleanupExpired() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for uuid, ticket := range l.tickets {
		if ticket.ExpiresAt != nil && ticket.ExpiresAt.AsTime().Before(now) {
			delete(l.tickets, uuid)
		}
	}
}

// startCleanupRoutine runs a background task to clean expired tickets.
func (l *InMemoryLedger) startCleanupRoutine(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		l.CleanupExpired()
	}
}

// GetTicket retrieves a ticket by its UUID without consuming it.
func (l *InMemoryLedger) GetTicket(uuid string) (*enclave.PermitTicket, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ticket, exists := l.tickets[uuid]
	if !exists {
		return nil, false
	}

	// Return a clone of the ticket to prevent external modifications
	cloned := proto.Clone(ticket).(*enclave.PermitTicket)
	return cloned, true
}

// ListTickets returns all tickets in the ledger.
func (l *InMemoryLedger) ListTickets() []*enclave.PermitTicket {
	l.mu.Lock()
	defer l.mu.Unlock()

	tickets := make([]*enclave.PermitTicket, 0, len(l.tickets))
	for _, ticket := range l.tickets {
		// Clone each ticket to prevent external modifications
		cloned := proto.Clone(ticket).(*enclave.PermitTicket)
		tickets = append(tickets, cloned)
	}
	return tickets
}
