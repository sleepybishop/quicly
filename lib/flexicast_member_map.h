#ifndef flexicast_member_map_h
#define flexicast_member_map_h

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct st_flexicast_member_entry_t {
    uint64_t id;
    size_t slot;
} flexicast_member_entry_t;

typedef struct st_flexicast_member_map_t {
    flexicast_member_entry_t *entries;
    size_t capacity;
} flexicast_member_map_t;

static inline size_t flexicast_member_hash(uint64_t id)
{
    id ^= id >> 30;
    id *= UINT64_C(0xbf58476d1ce4e5b9);
    id ^= id >> 27;
    id *= UINT64_C(0x94d049bb133111eb);
    return (size_t)(id ^ (id >> 31));
}

static inline void flexicast_member_map_dispose(flexicast_member_map_t *map)
{
    free(map->entries);
    map->entries = NULL;
    map->capacity = 0;
}

static inline flexicast_member_entry_t *flexicast_member_map_entry(const flexicast_member_map_t *map, uint64_t id)
{
    size_t mask = map->capacity - 1, i = flexicast_member_hash(id) & mask;
    assert(id != 0);
    while (map->entries[i].id != 0 && map->entries[i].id != id)
        i = (i + 1) & mask;
    return map->entries + i;
}

/* Keep the map at most half full so every probe reaches an empty entry. */
static inline int flexicast_member_map_reserve(flexicast_member_map_t *map, size_t members)
{
    if (map->capacity >= members * 2)
        return 0;
    size_t capacity = 2;
    while (capacity < members * 2)
        capacity *= 2;
    flexicast_member_map_t grown = {.entries = calloc(capacity, sizeof(*grown.entries)), .capacity = capacity};
    if (grown.entries == NULL)
        return -1;
    for (size_t i = 0; i != map->capacity; ++i)
        if (map->entries[i].id != 0)
            *flexicast_member_map_entry(&grown, map->entries[i].id) = map->entries[i];
    free(map->entries);
    *map = grown;
    return 0;
}

static inline int flexicast_member_map_find(const flexicast_member_map_t *map, uint64_t id)
{
    if (id == 0 || map->entries == NULL)
        return -1;
    const flexicast_member_entry_t *entry = flexicast_member_map_entry(map, id);
    return entry->id != 0 ? (int)entry->slot : -1;
}

static inline void flexicast_member_map_set(flexicast_member_map_t *map, uint64_t id, size_t slot)
{
    *flexicast_member_map_entry(map, id) = (flexicast_member_entry_t){id, slot};
}

static inline void flexicast_member_map_remove(flexicast_member_map_t *map, uint64_t id)
{
    if (map->entries == NULL)
        return;
    size_t mask = map->capacity - 1;
    size_t hole = (size_t)(flexicast_member_map_entry(map, id) - map->entries);
    if (map->entries[hole].id == 0)
        return;
    /* move entries whose probe crosses the hole; deletion leaves no tombstones */
    for (size_t i = (hole + 1) & mask; map->entries[i].id != 0; i = (i + 1) & mask) {
        size_t home = flexicast_member_hash(map->entries[i].id) & mask;
        if (((hole - home) & mask) < ((i - home) & mask)) {
            map->entries[hole] = map->entries[i];
            hole = i;
        }
    }
    map->entries[hole] = (flexicast_member_entry_t){0};
}

#endif
