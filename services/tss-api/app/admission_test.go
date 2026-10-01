package app

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	_interface "rosen-bridge/tss-api/app/interface"
	"rosen-bridge/tss-api/models"
)

type admissionKeygenOperation struct {
	_interface.KeygenOperation
	class string
}

func (o *admissionKeygenOperation) GetClassName() string { return o.class }

type admissionSignOperation struct {
	_interface.SignOperation
	class string
}

func (o *admissionSignOperation) GetClassName() string { return o.class }

func newAdmissionRegistry() *rosenTss {
	logging = zap.NewNop().Sugar()
	return &rosenTss{
		ChannelMap:         make(map[string]chan models.GossipMessage),
		KeygenOperationMap: make(map[string]_interface.KeygenOperation),
		SignOperationMap:   make(map[string]_interface.SignOperation),
		signClassMap:       make(map[string]string),
	}
}

func TestAdmissionRejectsOppositeKindInBothOrders(t *testing.T) {
	for _, crypto := range []string{models.ECDSA, models.EDDSA} {
		for _, signFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/signFirst=%t", crypto, signFirst), func(t *testing.T) {
				r := newAdmissionRegistry()
				keygenClass, signClass := crypto+"Keygen", crypto+"Sign"
				keygenCh, signCh := make(chan models.GossipMessage, 1), make(chan models.GossipMessage, 1)
				keygenOp, signOp := &admissionKeygenOperation{class: keygenClass}, &admissionSignOperation{class: signClass}
				keygen := func() error { return r.reserveKeygenInstance(keygenClass, keygenClass, keygenCh, keygenOp) }
				sign := func() error { return r.reserveSignInstance(crypto+"digest", signClass+"chain", signCh, signOp) }
				first, second, activeClass := keygen, sign, keygenClass
				if signFirst {
					first, second, activeClass = sign, keygen, signClass
				}
				if err := first(); err != nil {
					t.Fatal(err)
				}
				if err := second(); err == nil || err.Error() != activeClass+" "+models.OperationIsRunningError {
					t.Fatalf("opposite reservation: %v", err)
				}
				if len(r.ChannelMap) != 1 || len(r.KeygenOperationMap)+len(r.SignOperationMap) != 1 {
					t.Fatal("rejected reservation changed the registry")
				}
				if signFirst {
					r.deleteSignInstance(crypto+"digest", signClass+"chain", signCh, signOp)
				} else {
					r.deleteKeygenInstance(keygenClass, keygenClass, keygenCh, keygenOp)
				}
				if err := second(); err != nil {
					t.Fatalf("reservation after owner cleanup: %v", err)
				}
			})
		}
	}
}

func TestAdmissionConcurrentOppositeKinds(t *testing.T) {
	for _, crypto := range []string{models.ECDSA, models.EDDSA} {
		t.Run(crypto, func(t *testing.T) {
			r := newAdmissionRegistry()
			start := make(chan struct{})
			results := make(chan error, 2)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				results <- r.reserveKeygenInstance(crypto+"Keygen", crypto+"Keygen", make(chan models.GossipMessage, 1), &admissionKeygenOperation{class: crypto + "Keygen"})
			}()
			go func() {
				defer wg.Done()
				<-start
				results <- r.reserveSignInstance(crypto+"digest", crypto+"Sign-chain", make(chan models.GossipMessage, 1), &admissionSignOperation{class: crypto + "Sign"})
			}()
			close(start)
			wg.Wait()
			close(results)
			accepted, blocked := 0, 0
			for err := range results {
				if err == nil {
					accepted++
				} else if err.Error() == crypto+"Sign "+models.OperationIsRunningError || err.Error() == crypto+"Keygen "+models.OperationIsRunningError {
					blocked++
				} else {
					t.Fatal(err)
				}
			}
			if accepted != 1 || blocked != 1 || len(r.ChannelMap) != 1 {
				t.Fatalf("accepted=%d blocked=%d channels=%d", accepted, blocked, len(r.ChannelMap))
			}
		})
	}
}

func TestAdmissionUsesExactClassAndKeepsOtherCrypto(t *testing.T) {
	r := newAdmissionRegistry()
	if err := r.reserveSignInstance("eddsa-digest", "ecdsaSign-misleading", make(chan models.GossipMessage, 1), &admissionSignOperation{class: models.EDDSA + "Sign"}); err != nil {
		t.Fatal(err)
	}
	if err := r.reserveKeygenInstance("ecdsaKeygen", "ecdsaKeygen", make(chan models.GossipMessage, 1), &admissionKeygenOperation{class: models.ECDSA + "Keygen"}); err != nil {
		t.Fatalf("unrelated crypto blocked: %v", err)
	}
	if err := r.reserveKeygenInstance("eddsaKeygen", "eddsaKeygen", make(chan models.GossipMessage, 1), &admissionKeygenOperation{class: models.EDDSA + "Keygen"}); err == nil || err.Error() != "eddsaSign "+models.OperationIsRunningError {
		t.Fatalf("same-crypto admission: %v", err)
	}
	if len(r.ChannelMap) != 2 || len(r.KeygenOperationMap) != 1 || len(r.SignOperationMap) != 1 {
		t.Fatal("rejected reservation changed unrelated owners")
	}
}

func TestAdmissionOneSignCleanupKeepsOtherSignActive(t *testing.T) {
	r := newAdmissionRegistry()
	firstCh, secondCh := make(chan models.GossipMessage, 1), make(chan models.GossipMessage, 1)
	firstOp, secondOp := &admissionSignOperation{class: "ecdsaSign"}, &admissionSignOperation{class: "ecdsaSign"}
	if err := r.reserveSignInstance("digest1", "ecdsaSign-chain1", firstCh, firstOp); err != nil {
		t.Fatal(err)
	}
	if err := r.reserveSignInstance("digest2", "ecdsaSign-chain2", secondCh, secondOp); err != nil {
		t.Fatal(err)
	}
	r.deleteSignInstance("digest1", "ecdsaSign-chain1", firstCh, firstOp)
	if err := r.reserveKeygenInstance("ecdsaKeygen", "ecdsaKeygen", make(chan models.GossipMessage, 1), &admissionKeygenOperation{class: "ecdsaKeygen"}); err == nil || err.Error() != "ecdsaSign "+models.OperationIsRunningError {
		t.Fatalf("remaining sign must block keygen: %v", err)
	}
	r.deleteSignInstance("digest2", "ecdsaSign-chain2", secondCh, secondOp)
	if err := r.reserveKeygenInstance("ecdsaKeygen", "ecdsaKeygen", make(chan models.GossipMessage, 1), &admissionKeygenOperation{class: "ecdsaKeygen"}); err != nil {
		t.Fatalf("keygen after both signs finish: %v", err)
	}
}

func TestAdmissionStaleCleanupKeepsReplacement(t *testing.T) {
	for _, replaced := range []string{"channel", "operation"} {
		t.Run(replaced, func(t *testing.T) {
			r := newAdmissionRegistry()
			const id, channelID = "ecdsa-digest", "ecdsaSign-chain"
			oldCh, newCh := make(chan models.GossipMessage, 1), make(chan models.GossipMessage, 1)
			oldOp, newOp := &admissionSignOperation{class: "ecdsaSign"}, &admissionSignOperation{class: "eddsaSign"}
			if err := r.reserveSignInstance(id, channelID, oldCh, oldOp); err != nil {
				t.Fatal(err)
			}
			r.registryMu.Lock()
			if replaced == "channel" {
				r.ChannelMap[id] = newCh
			} else {
				r.SignOperationMap[channelID] = newOp
			}
			r.signClassMap[channelID] = "eddsaSign"
			r.registryMu.Unlock()
			r.deleteSignInstance(id, channelID, oldCh, oldOp)
			if r.signClassMap[channelID] != "eddsaSign" {
				t.Fatal("stale cleanup removed replacement class")
			}
			if replaced == "channel" && (r.ChannelMap[id] != newCh || r.SignOperationMap[channelID] != oldOp) {
				t.Fatal("stale cleanup changed replacement channel owner")
			}
			if replaced == "operation" && (r.ChannelMap[id] != oldCh || r.SignOperationMap[channelID] != newOp) {
				t.Fatal("stale cleanup changed replacement operation owner")
			}
		})
	}
}

func TestAdmissionStaleKeygenCleanupKeepsReplacement(t *testing.T) {
	for _, replaced := range []string{"channel", "operation"} {
		t.Run(replaced, func(t *testing.T) {
			r := newAdmissionRegistry()
			const id = "ecdsaKeygen"
			oldCh, newCh := make(chan models.GossipMessage, 1), make(chan models.GossipMessage, 1)
			oldOp, newOp := &admissionKeygenOperation{class: id}, &admissionKeygenOperation{class: id}
			if err := r.reserveKeygenInstance(id, id, oldCh, oldOp); err != nil {
				t.Fatal(err)
			}
			r.registryMu.Lock()
			if replaced == "channel" {
				r.ChannelMap[id] = newCh
			} else {
				r.KeygenOperationMap[id] = newOp
			}
			r.registryMu.Unlock()
			r.deleteKeygenInstance(id, id, oldCh, oldOp)
			if replaced == "channel" && (r.ChannelMap[id] != newCh || r.KeygenOperationMap[id] != oldOp) {
				t.Fatal("stale cleanup changed replacement channel owner")
			}
			if replaced == "operation" && (r.ChannelMap[id] != oldCh || r.KeygenOperationMap[id] != newOp) {
				t.Fatal("stale cleanup changed replacement operation owner")
			}
			if err := r.reserveSignInstance("ecdsa-digest", "ecdsaSign-chain", make(chan models.GossipMessage, 1), &admissionSignOperation{class: "ecdsaSign"}); err == nil || err.Error() != id+" "+models.OperationIsRunningError {
				t.Fatalf("replacement keygen must block sign: %v", err)
			}
		})
	}
}

func TestAdmissionTimeoutCancellation(t *testing.T) {
	r := newAdmissionRegistry()
	errors := make(chan error, 1)
	cancel := r.timeOutGoRoutine("ecdsaSign", 2, errors)
	start := time.Now()
	cancel()
	if time.Since(start) > time.Second {
		t.Fatal("cancel waited for operation timeout")
	}
	select {
	case err := <-errors:
		t.Fatalf("canceled timeout delivered an error: %v", err)
	case <-time.After(2100 * time.Millisecond):
	}

	expired := make(chan error, 1)
	cancelExpired := r.timeOutGoRoutine("ecdsaSign", 0, expired)
	select {
	case err := <-expired:
		if err == nil || err.Error() != "ecdsaSign operation timeout" {
			t.Fatalf("timeout result: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("zero-second timeout did not deliver an error")
	}
	cancelExpired()
	cancelExpired()
}
