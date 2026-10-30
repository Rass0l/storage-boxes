package app

import (
	"sync"
	"time"

	"github.com/Rass0l/storage-boxes/internal/platform/clock"
)

// UnlockCache holds unwrapped box master keys in memory for the duration of
// an unlock session. Keys are automatically evicted when the corresponding
// UnlockSession is deleted or expires.
//
// BMKs are never persisted — see docs/implementation/unlock-session-durability.md.
// An API restart drops every cached BMK; clients re-unlock with the box
// password to continue.
type UnlockCache struct {
	mu    sync.RWMutex
	items map[string]unlockCacheItem
	clock clock.Clock
}

type unlockCacheItem struct {
	BoxID     string
	UserID    string
	BMK       []byte
	ExpiresAt time.Time
}

func NewUnlockCache(clk clock.Clock) *UnlockCache {
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &UnlockCache{items: map[string]unlockCacheItem{}, clock: clk}
}

func (c *UnlockCache) Put(sessionID, boxID, userID string, bmk []byte, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	buf := make([]byte, len(bmk))
	copy(buf, bmk)
	c.items[sessionID] = unlockCacheItem{BoxID: boxID, UserID: userID, BMK: buf, ExpiresAt: expiresAt}
}

type UnlockContext struct {
	BoxID  string
	UserID string
	BMK    []byte
}

func (c *UnlockCache) Lookup(sessionID string) (UnlockContext, bool) {
	c.mu.RLock()
	item, ok := c.items[sessionID]
	c.mu.RUnlock()
	if !ok {
		return UnlockContext{}, false
	}
	if !item.ExpiresAt.After(c.clock.Now()) {
		c.mu.Lock()
		delete(c.items, sessionID)
		c.mu.Unlock()
		return UnlockContext{}, false
	}
	return UnlockContext{BoxID: item.BoxID, UserID: item.UserID, BMK: item.BMK}, true
}

func (c *UnlockCache) Delete(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, sessionID)
}

// SweepBox drops every cached BMK for the given box. Called when a box
// is soft-deleted so a client holding an unlock-session token can't
// keep reading plaintext between now and worker finalize.
func (c *UnlockCache) SweepBox(boxID string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for k, v := range c.items {
		if v.BoxID == boxID {
			delete(c.items, k)
			removed++
		}
	}
	return removed
}

func (c *UnlockCache) Sweep(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	removed := 0
	for k, v := range c.items {
		if !v.ExpiresAt.After(now) {
			delete(c.items, k)
			removed++
		}
	}
	return removed
}
