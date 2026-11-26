package detector

import (
	"container/list"
	"hash/fnv"
	"sync"
)

const (
	numShards   = 64
	numBuckets  = 60
	maxDedupURI = 32
)

type uriHashSlot struct {
	hash uint64
	ts   int64
}

type windowEntry struct {
	key        string
	bucketSec  int64
	lastSlot   int64
	buckets    [numBuckets]uint16
	dedupSlots [maxDedupURI]uriHashSlot
	dedupCount int
	lastSeen   int64
}

type windowShard struct {
	mu      sync.Mutex
	maxSize int
	lru     *list.List
	items   map[string]*list.Element
}

// ShardedWindow is a bounded-memory, 64-shard LRU sliding window counter.
// Memory per tracked (ip, jail) entry is fixed-size to prevent OOM under IP spoofing floods.
type ShardedWindow struct {
	shards    [numShards]windowShard
	maxTotal  int
}

// NewShardedWindow creates a bounded sliding window tracking at most maxTotal keys.
func NewShardedWindow(maxTotal int) *ShardedWindow {
	if maxTotal < numShards {
		maxTotal = numShards
	}
	perShard := (maxTotal + numShards - 1) / numShards
	sw := &ShardedWindow{maxTotal: maxTotal}
	for i := range sw.shards {
		sw.shards[i] = windowShard{
			maxSize: perShard,
			lru:     list.New(),
			items:   make(map[string]*list.Element, min(perShard, 128)),
		}
	}
	return sw
}

func shardIndex(key string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32() % numShards)
}

func hashURIPath(path string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(path))
	return h.Sum64()
}

// Record increments the sliding window counter for (ip, jailID) at timestamp nowSec,
// optionally deduplicating by uriPath, and returns the total hit count within windowSec.
func (sw *ShardedWindow) Record(ip, jailID string, nowSec int64, windowSec int, dedupURI bool, uriPath string) int {
	if windowSec <= 0 {
		windowSec = 60
	}
	bucketSec := int64((windowSec + numBuckets - 1) / numBuckets)
	if bucketSec < 1 {
		bucketSec = 1
	}

	key := ip + "\x00" + jailID
	sh := &sw.shards[shardIndex(key)]

	sh.mu.Lock()
	defer sh.mu.Unlock()

	var entry *windowEntry
	if el, ok := sh.items[key]; ok {
		sh.lru.MoveToFront(el)
		entry = el.Value.(*windowEntry)
	} else {
		if sh.lru.Len() >= sh.maxSize {
			if back := sh.lru.Back(); back != nil {
				old := back.Value.(*windowEntry)
				delete(sh.items, old.key)
				sh.lru.Remove(back)
			}
		}
		entry = &windowEntry{
			key:       key,
			bucketSec: bucketSec,
			lastSlot:  nowSec / bucketSec,
		}
		el := sh.lru.PushFront(entry)
		sh.items[key] = el
	}

	entry.lastSeen = nowSec

	// Reset if bucket width changed (e.g. jail window reconfigured).
	if entry.bucketSec != bucketSec {
		entry.bucketSec = bucketSec
		entry.lastSlot = nowSec / bucketSec
		entry.buckets = [numBuckets]uint16{}
		entry.dedupCount = 0
	}

	// Optional URI deduplication within the active window.
	if dedupURI {
		cutoff := nowSec - int64(windowSec)
		h := hashURIPath(uriPath)
		// Prune expired hashes and check for duplicate.
		writeIdx := 0
		seen := false
		for i := 0; i < entry.dedupCount; i++ {
			slot := entry.dedupSlots[i]
			if slot.ts <= cutoff {
				continue
			}
			if slot.hash == h {
				slot.ts = nowSec
				seen = true
			}
			entry.dedupSlots[writeIdx] = slot
			writeIdx++
		}
		entry.dedupCount = writeIdx
		if seen {
			return entry.count(nowSec, windowSec)
		}
		if entry.dedupCount < maxDedupURI {
			entry.dedupSlots[entry.dedupCount] = uriHashSlot{hash: h, ts: nowSec}
			entry.dedupCount++
		} else {
			// Replace the oldest slot when at capacity.
			oldestIdx := 0
			for i := 1; i < maxDedupURI; i++ {
				if entry.dedupSlots[i].ts < entry.dedupSlots[oldestIdx].ts {
					oldestIdx = i
				}
			}
			entry.dedupSlots[oldestIdx] = uriHashSlot{hash: h, ts: nowSec}
		}
	}

	// Advance ring buffer buckets.
	curSlot := nowSec / bucketSec
	if curSlot > entry.lastSlot {
		diff := curSlot - entry.lastSlot
		if diff >= numBuckets {
			entry.buckets = [numBuckets]uint16{}
		} else {
			for step := int64(1); step <= diff; step++ {
				idx := (entry.lastSlot + step) % numBuckets
				if idx < 0 {
					idx += numBuckets
				}
				entry.buckets[idx] = 0
			}
		}
		entry.lastSlot = curSlot
	}

	idx := curSlot % numBuckets
	if idx < 0 {
		idx += numBuckets
	}
	if entry.buckets[idx] < ^uint16(0) {
		entry.buckets[idx]++
	}

	return entry.count(nowSec, windowSec)
}

func (e *windowEntry) count(nowSec int64, windowSec int) int {
	curSlot := nowSec / e.bucketSec
	slotsInWindow := int64((windowSec + int(e.bucketSec) - 1) / int(e.bucketSec))
	if slotsInWindow > numBuckets {
		slotsInWindow = numBuckets
	}
	if curSlot-e.lastSlot >= slotsInWindow {
		return 0
	}

	total := 0
	minSlot := curSlot - slotsInWindow + 1
	for i := int64(0); i < numBuckets; i++ {
		slotNum := e.lastSlot - i
		if slotNum < minSlot {
			break
		}
		idx := slotNum % numBuckets
		if idx < 0 {
			idx += numBuckets
		}
		total += int(e.buckets[idx])
	}
	return total
}

// Clear removes a tracked (ip, jailID) entry, typically after banning.
func (sw *ShardedWindow) Clear(ip, jailID string) {
	key := ip + "\x00" + jailID
	sh := &sw.shards[shardIndex(key)]
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if el, ok := sh.items[key]; ok {
		delete(sh.items, key)
		sh.lru.Remove(el)
	}
}

// Size returns the total number of currently tracked entries across all shards.
func (sw *ShardedWindow) Size() int {
	total := 0
	for i := range sw.shards {
		sh := &sw.shards[i]
		sh.mu.Lock()
		total += sh.lru.Len()
		sh.mu.Unlock()
	}
	return total
}
