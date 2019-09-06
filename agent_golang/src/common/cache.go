package common

import (
	"github.com/allegro/bigcache"
	"time"
)

func NewCache(ttl int, MaxEntrySize int, HardMaxCacheSize int) (*bigcache.BigCache, error) {
	config := bigcache.Config{
		// number of shards (must be a power of 2)
		Shards: 1024,
		// time after which entry can be evicted
		LifeWindow:  time.Duration(ttl) * time.Second,
		CleanWindow: 15 * time.Second,
		// rps * lifeWindow, used only in initial memory allocation
		MaxEntriesInWindow: 1000 * 10 * 60,
		// max entry size in bytes, used only in initial memory allocation
		MaxEntrySize: MaxEntrySize,
		// prints information about additional memory allocation
		Verbose: false,
		// cache will not allocate more memory than this limit, value in MB
		// if value is reached then the oldest entries can be overridden for the new ones
		// 0 value means no size limit
		HardMaxCacheSize: HardMaxCacheSize,
		// callback fired when the oldest entry is removed because of its expiration time or no space left
		// for the new entry, or because delete was called. A bitmask representing the reason will be returned.
		// Default value is nil which means no callback and it prevents from unwrapping the oldest entry.
		OnRemove: nil,
		// OnRemoveWithReason is a callback fired when the oldest entry is removed because of its expiration time or no space left
		// for the new entry, or because delete was called. A constant representing the reason will be passed through.
		// Default value is nil which means no callback and it prevents from unwrapping the oldest entry.
		// Ignored if OnRemove is specified.
		OnRemoveWithReason: nil,
	}

	cache, initErr := bigcache.NewBigCache(config)
	return cache, initErr
}

func GetGlobalCache() *bigcache.BigCache {
	c, err := NewCache(120, 2048, 64)
	if err != nil {
		Logger.Error().Err(err)
		return nil
	}

	return c
}
