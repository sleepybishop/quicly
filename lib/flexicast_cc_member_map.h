/* Internal dense member table index shared by the built-in Flexicast CCs. */
#ifndef flexicast_cc_member_map_h
#define flexicast_cc_member_map_h

#include <stdint.h>
#include <stdlib.h>

typedef struct st_flexicast_cc_member_map_entry_t {
    uint64_t id;
    size_t slot;
    uint8_t state;
} flexicast_cc_member_map_entry_t;

typedef struct st_flexicast_cc_member_map_t {
    flexicast_cc_member_map_entry_t *entries;
    size_t capacity;
} flexicast_cc_member_map_t;

#define FLEXICAST_CC_MAP_EMPTY 0
#define FLEXICAST_CC_MAP_OCCUPIED 1
#define FLEXICAST_CC_MAP_TOMBSTONE 2

static uint64_t flexicast_cc_member_hash(uint64_t value)
{
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
}

static int flexicast_cc_member_map_init(flexicast_cc_member_map_t *map, size_t maximum_members)
{
    for (map->capacity = 2; map->capacity < maximum_members * 2; map->capacity *= 2)
        ;
    return (map->entries = calloc(map->capacity, sizeof(*map->entries))) != NULL ? 0 : -1;
}

static void flexicast_cc_member_map_dispose(flexicast_cc_member_map_t *map)
{
    free(map->entries);
    map->entries = NULL;
    map->capacity = 0;
}

static int flexicast_cc_member_map_find(const flexicast_cc_member_map_t *map, uint64_t id, size_t *slot)
{
    size_t index = (size_t)flexicast_cc_member_hash(id) & (map->capacity - 1);
    for (size_t probe = 0; probe != map->capacity; ++probe) {
        const flexicast_cc_member_map_entry_t *entry = map->entries + index;
        if (entry->state == FLEXICAST_CC_MAP_EMPTY)
            return -1;
        if (entry->state == FLEXICAST_CC_MAP_OCCUPIED && entry->id == id) {
            *slot = entry->slot;
            return 0;
        }
        index = (index + 1) & (map->capacity - 1);
    }
    return -1;
}

static int flexicast_cc_member_map_insert(flexicast_cc_member_map_t *map, uint64_t id, size_t slot)
{
    size_t index = (size_t)flexicast_cc_member_hash(id) & (map->capacity - 1), tombstone = SIZE_MAX;
    for (size_t probe = 0; probe != map->capacity; ++probe) {
        flexicast_cc_member_map_entry_t *entry = map->entries + index;
        if (entry->state == FLEXICAST_CC_MAP_OCCUPIED) {
            if (entry->id == id)
                return -1;
        } else if (entry->state == FLEXICAST_CC_MAP_TOMBSTONE) {
            if (tombstone == SIZE_MAX)
                tombstone = index;
        } else {
            if (tombstone != SIZE_MAX)
                entry = map->entries + tombstone;
            entry->id = id;
            entry->slot = slot;
            entry->state = FLEXICAST_CC_MAP_OCCUPIED;
            return 0;
        }
        index = (index + 1) & (map->capacity - 1);
    }
    return -1;
}

static void flexicast_cc_member_map_remove(flexicast_cc_member_map_t *map, uint64_t id)
{
    size_t slot, index;
    if (flexicast_cc_member_map_find(map, id, &slot) != 0)
        return;
    (void)slot;
    index = (size_t)flexicast_cc_member_hash(id) & (map->capacity - 1);
    while (map->entries[index].state != FLEXICAST_CC_MAP_EMPTY) {
        flexicast_cc_member_map_entry_t *entry = map->entries + index;
        if (entry->state == FLEXICAST_CC_MAP_OCCUPIED && entry->id == id) {
            entry->id = 0;
            entry->slot = 0;
            entry->state = FLEXICAST_CC_MAP_TOMBSTONE;
            return;
        }
        index = (index + 1) & (map->capacity - 1);
    }
}

static void flexicast_cc_member_map_update(flexicast_cc_member_map_t *map, uint64_t id, size_t slot)
{
    size_t index = (size_t)flexicast_cc_member_hash(id) & (map->capacity - 1);
    while (map->entries[index].state != FLEXICAST_CC_MAP_EMPTY) {
        flexicast_cc_member_map_entry_t *entry = map->entries + index;
        if (entry->state == FLEXICAST_CC_MAP_OCCUPIED && entry->id == id) {
            entry->slot = slot;
            return;
        }
        index = (index + 1) & (map->capacity - 1);
    }
}

#endif
