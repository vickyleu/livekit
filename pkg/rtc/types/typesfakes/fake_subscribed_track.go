// Code generated by counterfeiter. DO NOT EDIT.
package typesfakes

import (
	"sync"

	"github.com/livekit/livekit-server/pkg/rtc/types"
	"github.com/pion/ion-sfu/pkg/sfu"
)

type FakeSubscribedTrack struct {
	DownTrackStub        func() *sfu.DownTrack
	downTrackMutex       sync.RWMutex
	downTrackArgsForCall []struct {
	}
	downTrackReturns struct {
		result1 *sfu.DownTrack
	}
	downTrackReturnsOnCall map[int]struct {
		result1 *sfu.DownTrack
	}
	IsMutedStub        func() bool
	isMutedMutex       sync.RWMutex
	isMutedArgsForCall []struct {
	}
	isMutedReturns struct {
		result1 bool
	}
	isMutedReturnsOnCall map[int]struct {
		result1 bool
	}
	ResyncStub        func()
	resyncMutex       sync.RWMutex
	resyncArgsForCall []struct {
	}
	SetMutedStub        func(bool)
	setMutedMutex       sync.RWMutex
	setMutedArgsForCall []struct {
		arg1 bool
	}
	SetPublisherMutedStub        func(bool)
	setPublisherMutedMutex       sync.RWMutex
	setPublisherMutedArgsForCall []struct {
		arg1 bool
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeSubscribedTrack) DownTrack() *sfu.DownTrack {
	fake.downTrackMutex.Lock()
	ret, specificReturn := fake.downTrackReturnsOnCall[len(fake.downTrackArgsForCall)]
	fake.downTrackArgsForCall = append(fake.downTrackArgsForCall, struct {
	}{})
	stub := fake.DownTrackStub
	fakeReturns := fake.downTrackReturns
	fake.recordInvocation("DownTrack", []interface{}{})
	fake.downTrackMutex.Unlock()
	if stub != nil {
		return stub()
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *FakeSubscribedTrack) DownTrackCallCount() int {
	fake.downTrackMutex.RLock()
	defer fake.downTrackMutex.RUnlock()
	return len(fake.downTrackArgsForCall)
}

func (fake *FakeSubscribedTrack) DownTrackCalls(stub func() *sfu.DownTrack) {
	fake.downTrackMutex.Lock()
	defer fake.downTrackMutex.Unlock()
	fake.DownTrackStub = stub
}

func (fake *FakeSubscribedTrack) DownTrackReturns(result1 *sfu.DownTrack) {
	fake.downTrackMutex.Lock()
	defer fake.downTrackMutex.Unlock()
	fake.DownTrackStub = nil
	fake.downTrackReturns = struct {
		result1 *sfu.DownTrack
	}{result1}
}

func (fake *FakeSubscribedTrack) DownTrackReturnsOnCall(i int, result1 *sfu.DownTrack) {
	fake.downTrackMutex.Lock()
	defer fake.downTrackMutex.Unlock()
	fake.DownTrackStub = nil
	if fake.downTrackReturnsOnCall == nil {
		fake.downTrackReturnsOnCall = make(map[int]struct {
			result1 *sfu.DownTrack
		})
	}
	fake.downTrackReturnsOnCall[i] = struct {
		result1 *sfu.DownTrack
	}{result1}
}

func (fake *FakeSubscribedTrack) IsMuted() bool {
	fake.isMutedMutex.Lock()
	ret, specificReturn := fake.isMutedReturnsOnCall[len(fake.isMutedArgsForCall)]
	fake.isMutedArgsForCall = append(fake.isMutedArgsForCall, struct {
	}{})
	stub := fake.IsMutedStub
	fakeReturns := fake.isMutedReturns
	fake.recordInvocation("IsMuted", []interface{}{})
	fake.isMutedMutex.Unlock()
	if stub != nil {
		return stub()
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *FakeSubscribedTrack) IsMutedCallCount() int {
	fake.isMutedMutex.RLock()
	defer fake.isMutedMutex.RUnlock()
	return len(fake.isMutedArgsForCall)
}

func (fake *FakeSubscribedTrack) IsMutedCalls(stub func() bool) {
	fake.isMutedMutex.Lock()
	defer fake.isMutedMutex.Unlock()
	fake.IsMutedStub = stub
}

func (fake *FakeSubscribedTrack) IsMutedReturns(result1 bool) {
	fake.isMutedMutex.Lock()
	defer fake.isMutedMutex.Unlock()
	fake.IsMutedStub = nil
	fake.isMutedReturns = struct {
		result1 bool
	}{result1}
}

func (fake *FakeSubscribedTrack) IsMutedReturnsOnCall(i int, result1 bool) {
	fake.isMutedMutex.Lock()
	defer fake.isMutedMutex.Unlock()
	fake.IsMutedStub = nil
	if fake.isMutedReturnsOnCall == nil {
		fake.isMutedReturnsOnCall = make(map[int]struct {
			result1 bool
		})
	}
	fake.isMutedReturnsOnCall[i] = struct {
		result1 bool
	}{result1}
}

func (fake *FakeSubscribedTrack) Resync() {
	fake.resyncMutex.Lock()
	fake.resyncArgsForCall = append(fake.resyncArgsForCall, struct {
	}{})
	stub := fake.ResyncStub
	fake.recordInvocation("Resync", []interface{}{})
	fake.resyncMutex.Unlock()
	if stub != nil {
		fake.ResyncStub()
	}
}

func (fake *FakeSubscribedTrack) ResyncCallCount() int {
	fake.resyncMutex.RLock()
	defer fake.resyncMutex.RUnlock()
	return len(fake.resyncArgsForCall)
}

func (fake *FakeSubscribedTrack) ResyncCalls(stub func()) {
	fake.resyncMutex.Lock()
	defer fake.resyncMutex.Unlock()
	fake.ResyncStub = stub
}

func (fake *FakeSubscribedTrack) SetMuted(arg1 bool) {
	fake.setMutedMutex.Lock()
	fake.setMutedArgsForCall = append(fake.setMutedArgsForCall, struct {
		arg1 bool
	}{arg1})
	stub := fake.SetMutedStub
	fake.recordInvocation("SetMuted", []interface{}{arg1})
	fake.setMutedMutex.Unlock()
	if stub != nil {
		fake.SetMutedStub(arg1)
	}
}

func (fake *FakeSubscribedTrack) SetMutedCallCount() int {
	fake.setMutedMutex.RLock()
	defer fake.setMutedMutex.RUnlock()
	return len(fake.setMutedArgsForCall)
}

func (fake *FakeSubscribedTrack) SetMutedCalls(stub func(bool)) {
	fake.setMutedMutex.Lock()
	defer fake.setMutedMutex.Unlock()
	fake.SetMutedStub = stub
}

func (fake *FakeSubscribedTrack) SetMutedArgsForCall(i int) bool {
	fake.setMutedMutex.RLock()
	defer fake.setMutedMutex.RUnlock()
	argsForCall := fake.setMutedArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeSubscribedTrack) SetPublisherMuted(arg1 bool) {
	fake.setPublisherMutedMutex.Lock()
	fake.setPublisherMutedArgsForCall = append(fake.setPublisherMutedArgsForCall, struct {
		arg1 bool
	}{arg1})
	stub := fake.SetPublisherMutedStub
	fake.recordInvocation("SetPublisherMuted", []interface{}{arg1})
	fake.setPublisherMutedMutex.Unlock()
	if stub != nil {
		fake.SetPublisherMutedStub(arg1)
	}
}

func (fake *FakeSubscribedTrack) SetPublisherMutedCallCount() int {
	fake.setPublisherMutedMutex.RLock()
	defer fake.setPublisherMutedMutex.RUnlock()
	return len(fake.setPublisherMutedArgsForCall)
}

func (fake *FakeSubscribedTrack) SetPublisherMutedCalls(stub func(bool)) {
	fake.setPublisherMutedMutex.Lock()
	defer fake.setPublisherMutedMutex.Unlock()
	fake.SetPublisherMutedStub = stub
}

func (fake *FakeSubscribedTrack) SetPublisherMutedArgsForCall(i int) bool {
	fake.setPublisherMutedMutex.RLock()
	defer fake.setPublisherMutedMutex.RUnlock()
	argsForCall := fake.setPublisherMutedArgsForCall[i]
	return argsForCall.arg1
}

func (fake *FakeSubscribedTrack) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.downTrackMutex.RLock()
	defer fake.downTrackMutex.RUnlock()
	fake.isMutedMutex.RLock()
	defer fake.isMutedMutex.RUnlock()
	fake.resyncMutex.RLock()
	defer fake.resyncMutex.RUnlock()
	fake.setMutedMutex.RLock()
	defer fake.setMutedMutex.RUnlock()
	fake.setPublisherMutedMutex.RLock()
	defer fake.setPublisherMutedMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeSubscribedTrack) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ types.SubscribedTrack = new(FakeSubscribedTrack)
