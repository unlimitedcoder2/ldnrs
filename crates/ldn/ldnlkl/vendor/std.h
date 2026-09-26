/**
Copyright 2026 Alex Howe

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef STD_H
#define STD_H

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifdef __linux__
#include <sys/random.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#endif

#ifndef STD_ASSERT
#include <assert.h>
#define STD_ASSERT assert
#endif

#define UNUSED(x) (void) x;

#define MAX_U8 UCHAR_MAX
#define MAX_I32 INT32_MAX
#define MAX_U32 UINT32_MAX

#define STATIC_ARRAY_LEN(x) sizeof(x) / sizeof(x[0])

typedef uintptr_t uptr;

typedef size_t usize;

#ifdef __linux__
typedef ssize_t isize;
#elif _WIN32
typedef SSIZE_T isize;
#endif

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef float f32;
typedef double f64;

#ifdef _WIN32
typedef SOCKET Fd;
#else
typedef i32 Fd;
#endif

#ifndef _MSC_VER
#define NODISCARD [[nodiscard]]
#else
#define NODISCARD
#endif

#define IN
#define OUT

typedef struct {
	u8 *data;
	usize size;
} Std_Bytes;

static inline bool std_streq(const char *a, const char *b) { return strcmp(a, b) == 0; }

#define da_foreach(it, da) for (__typeof__(*(da)->items) *it = (da)->items; it < (da)->items + (da)->count; ++it)

typedef void *(*Std_Alloc_Fn)(void *userdata, usize size);

typedef void *(*Std_Realloc_Fn)(void *userdata, void *mem, usize size);

typedef void (*Std_Free_Fn)(void *userdata, void *mem);

typedef struct {
	Std_Alloc_Fn alloc;
	Std_Free_Fn free;
	void *userdata;
} Std_Allocator;

bool bytes_reserve(Std_Bytes *reader, Std_Allocator *allocator, usize size);

typedef struct {
	const char *str;
	u32 length;
} Std_String;

typedef struct Std_RefString Std_RefString;

struct Std_RefString {
	u16 count;
	Std_String str;
};

typedef struct Std_RefStrings_Page Std_RefStrings_Page;

struct Std_RefStrings_Page {
	Std_RefStrings_Page *next;
	usize count;
	Std_RefString items[];
};

typedef struct {
	Std_RefStrings_Page *first;
	Std_RefStrings_Page *last;
} Std_RefStrings;

typedef struct {
	Std_String *items;
	usize count;
	usize capacity;
} Std_Strings;

typedef struct {
	Std_RefStrings refs;
	char* buf;
	usize buf_offset;
	usize buf_capacity;
	Std_Allocator *allocator;
} Std_StringPool;

bool std_sp_alloc_string(Std_StringPool *sp, Std_String str, Std_RefString **ref_str);

static inline void std_sp_free(Std_RefString *ref) {
	STD_ASSERT(ref->count > 0);
	ref->count--;
}

void std_sp_compact(Std_StringPool *sp);

#define std_sp_new(allocator_) ((Std_StringPool){ .allocator = allocator_ })

static inline Std_String std_string_from_cstr(const char *s) {
	return (Std_String) {.str = s, .length = (u32) strlen(s)};
}

static inline bool std_str_eq(Std_String a, Std_String b) {
	return a.length == b.length && (a.str == b.str || (memcmp(a.str, b.str, a.length) == 0));
}

Std_String std_string_from_cstr_copy(Std_Allocator *allocator, const char *s);

char *std_strdup(Std_Allocator *allocator, const char *s);

static inline void *std_alloc(Std_Allocator *allocator, usize size) {
	return allocator->alloc(allocator->userdata, size);
}

static inline void *std_allocz(Std_Allocator *allocator, usize size) {
	void* block = allocator->alloc(allocator->userdata, size);
	if (block != NULL) {
		memset(block, 0, size);
	}
	return block;
}

static inline void std_free(Std_Allocator *allocator, void *mem) { allocator->free(allocator->userdata, mem); }

u32 std_read_u32_be(u8 *data);

u64 std_read_u64_be(u8 *data);

void std_write_u64_be(u8 *dest, u64 val);

void std_write_u32_be(u8 *dest, u32 val);

// from https://github.com/camgunz/cmp/blob/9b8fa1ec9f409d4fa74281d4a57d6c2163bb1a86/cmp.c#L154

static inline bool std_is_bigendian(void) {
	return false;
}

static inline bool std_is_littleendian(void) {
	return true;
}

u16 std_be16(u16 x);

u32 std_be32(u32 x);

u64 std_be64(u64 x);

static inline i16 std_sbe16(i16 x) { return (i16) std_be16((u16) x); }
static inline i32 std_sbe32(i32 x) { return (i32) std_be32((u32) x); }
static inline i64 std_sbe64(i64 x) { return (i64) std_be64((u64) x); }

f32 std_bef32(const i8 *b);

f64 std_bef64(const i8 *b);

u16 std_le16(u16 x);

u32 std_le32(u32 x);

u64 std_le64(u64 x);

static inline i16 std_sle16(i16 x) { return (i16) std_le16((u16) x); }
static inline i32 std_sle32(i32 x) { return (i32) std_le32((u32) x); }
static inline i64 std_sle64(i64 x) { return (i64) std_le64((u64) x); }

f32 std_lef32(const i8 *b);

f64 std_lef64(const i8 *b);

void std_random(u8 *buf, usize len);

// end from

#define HAS_LIBC
#ifdef HAS_LIBC
static Std_Allocator SYSTEM_ALLOCATOR;

void std_print_u8s(const char *name, u8 *arr, usize len);

#endif

// --------------------------------------------- = arena.h by tsoding = --------

// Copyright 2022 Alexey Kutepov <reximkut@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

typedef struct Std_Arena_Region Std_Arena_Region;

struct Std_Arena_Region {
	Std_Arena_Region *next;
	usize count;
	usize capacity;
	uintptr_t data[];
};

typedef struct {
	Std_Allocator *allocator;
	Std_Arena_Region *begin, *end;
} Std_Arena;

typedef struct {
	Std_Allocator *allocator;
	char *items;
	usize count;
	usize capacity;
} Std_String_Builder;

Std_Allocator std_arena_allocator(Std_Arena *arena);

#if defined(__GNUC__) || defined(__clang__)
//   https://gcc.gnu.org/onlinedocs/gcc-4.7.2/gcc/Function-Attributes.html
#ifdef __MINGW_PRINTF_FORMAT
#define STD_PRINTF_FORMAT(STRING_INDEX, FIRST_TO_CHECK)                                                                \
	__attribute__((format(__MINGW_PRINTF_FORMAT, STRING_INDEX, FIRST_TO_CHECK)))
#else
#define STD_PRINTF_FORMAT(STRING_INDEX, FIRST_TO_CHECK) __attribute__((format(printf, STRING_INDEX, FIRST_TO_CHECK)))
#endif
#else
//   TODO: implement STD_PRINTF_FORMAT for MSVC
#define STD_PRINTF_FORMAT(STRING_INDEX, FIRST_TO_CHECK)
#endif

#define std_da_reserve(allocator, da, expected_capacity)                                                               \
	do {                                                                                                               \
		if ((expected_capacity) > (da)->capacity) {                                                                    \
			usize original_size = (da)->capacity * sizeof(*(da)->items);                                               \
			if ((da)->capacity == 0) {                                                                                 \
				(da)->capacity = ARENA_DA_INIT_CAP;                                                                    \
			}                                                                                                          \
			while ((expected_capacity) > (da)->capacity) {                                                             \
				(da)->capacity *= 2;                                                                                   \
			}                                                                                                          \
			(da)->items =                                                                                              \
					std_alloc_da(allocator, (da)->items, original_size, (da)->capacity * sizeof(*(da)->items));    \
			STD_ASSERT((da)->items != NULL && "Buy more RAM lol");                                                     \
		}                                                                                                              \
	} while (0)

#define std_da_append_many(allocator, da, new_items, new_items_count)                                                  \
	do {                                                                                                               \
		std_da_reserve(allocator, (da), (da)->count + (new_items_count));                                              \
		memcpy((da)->items + (da)->count, (new_items), (new_items_count) * sizeof(*(da)->items));                      \
		(da)->count += (new_items_count);                                                                              \
	} while (0)

i32 std_sb_appendf(Std_String_Builder *sb, const char *fmt, ...) STD_PRINTF_FORMAT(2, 3);

void std_sb_append_char_n(Std_String_Builder *sb, char c, usize n);
void std_sb_append_char(Std_String_Builder *sb, char c);

#define std_sb_append_buf(sb, buf, size) std_da_append_many((sb)->allocator, sb, buf, size)
#define sb_reset(sb) ((sb)->count = 0)

#define std_sb_append_cstr(sb, cstr)                                                                                   \
	do {                                                                                                               \
		const char *s = (cstr);                                                                                        \
		size_t n = strlen(s);                                                                                          \
		std_da_append_many((sb)->allocator, sb, s, n);                                                                  \
	} while (0)

#define std_sb_append_null(sb) std_da_append_many((sb)->allocator, sb, "", 1)

#define std_sb_free(sb) std_free((sb).allocator, (sb).items)

#define std_sb_new(allocator_) ((Std_String_Builder){ .allocator = (allocator_) })

#ifndef ARENA_REGION_DEFAULT_CAPACITY
#define ARENA_REGION_DEFAULT_CAPACITY (8 * 1024)
#endif

#ifndef STRINGPOOL_DEFAULT_COUNT
#define STRINGPOOL_DEFAULT_COUNT 1024
#endif

#ifndef STRINGPOOL_DEFAULT_CAPACITY
#define STRINGPOOL_DEFAULT_CAPACITY (16 * 1024)
#endif

Std_Arena_Region *std_region_new(Std_Allocator *allocator, usize capacity);

void std_region_free(Std_Allocator *allocator, Std_Arena_Region *r);

usize std_arena_memory_usage(Std_Arena *arena);

STD_PRINTF_FORMAT(2, 3) char *std_sprintf(Std_Allocator *a, const char *format, ...);

char *std_vsprintf(Std_Allocator *a, const char *format, va_list args);

void std_arena_free(Std_Arena *a);

#ifndef ARENA_DA_INIT_CAP
#define ARENA_DA_INIT_CAP 256
#endif

#ifdef __cplusplus
#define cast_ptr(ptr) (decltype(ptr))
#else
#define cast_ptr(...)
#endif

void *std_alloc_da(Std_Allocator *allocator, void *oldptr, size_t oldsz, size_t newsz);

#define da_clear(da) (da)->count = 0;

#define allocator_da_append(a, da, item)                                                                               \
	do {                                                                                                               \
		if ((da)->count >= (da)->capacity) {                                                                           \
			size_t new_capacity = (da)->capacity == 0 ? ARENA_DA_INIT_CAP : (da)->capacity * 2;                        \
			(da)->items = cast_ptr((da)->items) std_alloc_da((a), (da)->items, (da)->capacity * sizeof(*(da)->items),  \
															 new_capacity * sizeof(*(da)->items));                     \
			(da)->capacity = new_capacity;                                                                             \
		}                                                                                                              \
																													   \
		(da)->items[(da)->count++] = (item);                                                                           \
	} while (0)

#define arena_sb_append_buf arena_da_append_many

#define arena_sb_append_cstr(a, sb, cstr)                                                                              \
	do {                                                                                                               \
		const char *s = (cstr);                                                                                        \
		size_t n = arena_strlen(s);                                                                                    \
		arena_da_append_many(a, sb, s, n);                                                                             \
	} while (0)

#define arena_sb_append_null(a, sb) arena_da_append(a, sb, 0)

#endif

#ifdef STD_IMPLEMENTATION

const char *std_fmt(const char *format, ...) {
	va_list args;
	va_start(args, format);

	va_list args2;
	va_copy(args2, args);

	const usize len = vsnprintf(NULL, 0, format, args);
	char *buf = malloc(len + 1);
	if (buf == NULL) {
		return NULL;
	}

	vsnprintf(buf, len + 1, format, args2);

	va_end(args);

	return buf;
}

char *std_strdup(Std_Allocator *allocator, const char *s) {
	usize len = strlen(s);
	char *cpy = std_alloc(allocator, len + 1);
	if (cpy == NULL) {
		return NULL;
	}

	memcpy(cpy, s, len);
	cpy[len] = '\0';
	return cpy;
}

Std_String std_string_from_cstr_copy(Std_Allocator *allocator, const char *s) {
	char *cpy = std_strdup(allocator, s);
	usize len = strlen(s);
	return (Std_String) {.length = (u32) len, .str = cpy};
}

// --------------------------------------------- = arena.h by tsoding =
// ---------------------------------------------------------------------------------
char *std_vsprintf(Std_Allocator *a, const char *format, va_list args) {
	va_list args_copy;
	va_copy(args_copy, args);
	int n = vsnprintf(NULL, 0, format, args_copy);
	va_end(args_copy);

	if (n <= 0) {
		return "";
	}

	char *result = (char *) std_alloc(a, n + 1);
	vsnprintf(result, n + 1, format, args);

	return result;
}

#if defined(__GNUC__) || defined(__clang__)
#define CHECK_PRINTF_FMT(a, b) __attribute__((format(printf, a, b)))
#else
#define CHECK_PRINTF_FMT(...)
#endif
CHECK_PRINTF_FMT(2, 3) char *std_sprintf(Std_Allocator *a, const char *format, ...) {
	va_list args;
	va_start(args, format);
	char *result = std_vsprintf(a, format, args);
	va_end(args);

	return result;
}

Std_Arena_Region *std_region_new(Std_Allocator *allocator, size_t capacity) {
	size_t size_bytes = sizeof(Std_Arena_Region) + sizeof(uintptr_t) * capacity;
	Std_Arena_Region *r = (Std_Arena_Region *) std_alloc(allocator, size_bytes);
	if (r == NULL) {
		return NULL;
	}
	r->next = NULL;
	r->count = 0;
	r->capacity = capacity;
	return r;
}

void std_region_free(Std_Allocator *allocator, Std_Arena_Region *r) { std_free(allocator, r); }

void *arena_alloc(Std_Arena *a, size_t size_bytes) {
	size_t size = (size_bytes + sizeof(uintptr_t) - 1) / sizeof(uintptr_t);

	if (a->end == NULL) {
		STD_ASSERT(a->begin == NULL);
		size_t capacity = ARENA_REGION_DEFAULT_CAPACITY;
		if (capacity < size)
			capacity = size;
		a->end = std_region_new(a->allocator, capacity);
		a->begin = a->end;
	}

	while (a->end->count + size > a->end->capacity && a->end->next != NULL) {
		a->end = a->end->next;
	}

	if (a->end->count + size > a->end->capacity) {
		STD_ASSERT(a->end->next == NULL);
		size_t capacity = ARENA_REGION_DEFAULT_CAPACITY;
		if (capacity < size)
			capacity = size;
		a->end->next = std_region_new(a->allocator, capacity);
		a->end = a->end->next;
	}

	void *result = &a->end->data[a->end->count];
	a->end->count += size;
	return result;
}

size_t std_arena_memory_usage(Std_Arena *arena) {
	size_t mem_usage = 0;
	for (Std_Arena_Region *r = arena->begin; r != NULL; r = r->next) {
		mem_usage += sizeof(Std_Arena_Region) + (sizeof(uintptr_t) * r->capacity);
	}
	return mem_usage;
}

void arena_reset(Std_Arena *a) {
	for (Std_Arena_Region *r = a->begin; r != NULL; r = r->next) {
		r->count = 0;
	}

	a->end = a->begin;
}

void std_arena_free(Std_Arena *a) {
	Std_Arena_Region *r = a->begin;
	while (r) {
		Std_Arena_Region *r0 = r;
		r = r->next;
		std_region_free(a->allocator, r0);
	}
	a->begin = NULL;
	a->end = NULL;
}

void arena_trim(Std_Arena *a) {
	Std_Arena_Region *r = a->end->next;
	while (r) {
		Std_Arena_Region *r0 = r;
		r = r->next;
		std_region_free(a->allocator, r0);
	}
	a->end->next = NULL;
}

static void *std_allocator_arena_alloc(void *userdata, usize size) {
	Std_Arena *arena = userdata;
	return arena_alloc(arena, size);
}

static void std_allocator_arena_free(void *userdata, void *block) {
	(void) userdata;
	(void) block;
}

Std_Allocator std_arena_allocator(Std_Arena *arena) {
	return (Std_Allocator) {.userdata = arena, .alloc = std_allocator_arena_alloc, .free = std_allocator_arena_free};
}

#ifdef __linux__

void std_random(u8 *buf, usize len) {
	getrandom(buf, len, 0);
}

#elifdef _WIN32

#endif

#ifdef HAS_LIBC

static void *std_libc_alloc(void *userdata, usize size) {
	UNUSED(userdata);
	return malloc(size);
}

static void std_libc_free(void *userdata, void *block) {
	UNUSED(userdata);
	free(block);
}

static Std_Allocator SYSTEM_ALLOCATOR = {.alloc = std_libc_alloc, .free = std_libc_free};

void std_print_u8s(const char *name, u8 *arr, usize len) {
	printf("%s = { ", name);

	for (usize i = 0; i < len; i++) {
		u8 x = arr[i];
		if (i == 0) {
			printf("%u", x);
		} else {
			printf(", %u", x);
		}
	}

	printf(" }\n");
}

#endif

void *std_alloc_da(Std_Allocator *allocator, void *oldptr, size_t oldsz, size_t newsz) {
	void *mem = std_alloc(allocator, newsz);
	memcpy(mem, oldptr, oldsz);
	std_free(allocator, oldptr);
	return mem;
}

uint16_t std_be16(uint16_t x) {
	if (!std_is_bigendian()) {
		return ((x >> 8) & 0x00ff) | ((x << 8) & 0xff00);
	}

	return x;
}

uint32_t std_be32(uint32_t x) {
	if (!std_is_bigendian()) {
		return ((uint32_t) std_be16((uint16_t) (x >> 16))) | ((uint32_t) std_be16((uint16_t) (x & 0xffff)) << 16);
	}

	return x;
}

uint64_t std_be64(uint64_t x) {
	if (!std_is_bigendian()) {
		return ((uint64_t) std_be32((uint32_t) (x >> 32))) | ((uint64_t) std_be32((uint32_t) (x & 0xffffffff)) << 32);
	}

	return x;
}

f32 std_bef32(const i8 *b) {
	f32 f = 0.f;
	char *fb = (char *) &f;

	if (!std_is_bigendian()) {
		fb[0] = b[3];
		fb[1] = b[2];
		fb[2] = b[1];
		fb[3] = b[0];
	} else {
		fb[0] = b[0];
		fb[1] = b[1];
		fb[2] = b[2];
		fb[3] = b[3];
	}

	return f;
}

f64 std_bef64(const i8 *b) {
	double d = 0.;
	char *db = (char *) &d;

	if (!std_is_bigendian()) {
		db[0] = b[7];
		db[1] = b[6];
		db[2] = b[5];
		db[3] = b[4];
		db[4] = b[3];
		db[5] = b[2];
		db[6] = b[1];
		db[7] = b[0];
	} else {
		db[0] = b[0];
		db[1] = b[1];
		db[2] = b[2];
		db[3] = b[3];
		db[4] = b[4];
		db[5] = b[5];
		db[6] = b[6];
		db[7] = b[7];
	}

	return d;
}

uint16_t std_le16(uint16_t x) {
	if (std_is_bigendian()) {
		return ((x >> 8) & 0x00ff) | ((x << 8) & 0xff00);
	}

	return x;
}

uint32_t std_le32(uint32_t x) {
	if (std_is_bigendian()) {
		return ((uint32_t) std_le16((uint16_t) (x >> 16))) | ((uint32_t) std_le16((uint16_t) (x & 0xffff)) << 16);
	}

	return x;
}

uint64_t std_le64(uint64_t x) {
	if (std_is_bigendian()) {
		return ((uint64_t) std_le32((uint32_t) (x >> 32))) | ((uint64_t) std_le32((uint32_t) (x & 0xffffffff)) << 32);
	}

	return x;
}

f32 std_lef32(const i8 *b) {
	f32 f = 0.f;
	char *fb = (char *) &f;

	if (std_is_bigendian()) {
		fb[0] = b[3];
		fb[1] = b[2];
		fb[2] = b[1];
		fb[3] = b[0];
	} else {
		fb[0] = b[0];
		fb[1] = b[1];
		fb[2] = b[2];
		fb[3] = b[3];
	}

	return f;
}

f64 std_lef64(const i8 *b) {
	double d = 0.;
	char *db = (char *) &d;

	if (std_is_bigendian()) {
		db[0] = b[7];
		db[1] = b[6];
		db[2] = b[5];
		db[3] = b[4];
		db[4] = b[3];
		db[5] = b[2];
		db[6] = b[1];
		db[7] = b[0];
	} else {
		db[0] = b[0];
		db[1] = b[1];
		db[2] = b[2];
		db[3] = b[3];
		db[4] = b[4];
		db[5] = b[5];
		db[6] = b[6];
		db[7] = b[7];
	}

	return d;
}

u32 std_read_u32_be(u8 *data) {
	u32 tmp = 0;
	u32 *tmp_ptr = &tmp;

	memcpy(tmp_ptr, data, sizeof(u32));

	tmp = std_be32(tmp);

	return tmp;
}

u64 std_read_u64_be(u8 *data) {
	u64 tmp = 0;
	u64 *tmp_ptr = &tmp;

	memcpy(tmp_ptr, data, sizeof(u64));

	tmp = std_be64(tmp);

	return tmp;
}

void std_write_u64_be(u8 *dest, u64 val) {
	u64 tmp = std_be64(val);
	u64 *ptr = &tmp;
	memcpy(dest, ptr, sizeof(u64));
}

void std_write_u32_be(u8 *dest, u32 val) {
	u32 tmp = std_be32(val);
	u32 *ptr = &tmp;
	memcpy(dest, ptr, sizeof(u32));
}

bool bytes_reserve(Std_Bytes *bytes, Std_Allocator *allocator, usize size) {
	if (bytes->size >= size) {
		return true;
	}

	void *block = std_alloc(allocator, size);
	if (block == NULL) {
		return false;
	}

	memcpy(block, bytes->data, bytes->size);
	std_free(allocator, bytes->data);
	*bytes = (Std_Bytes) {.data = block, .size = size};

	return true;
}

void std_sb_append_char(Std_String_Builder *sb, char c) {
	std_sb_append_char_n(sb, c, 1);
}

void std_sb_append_char_n(Std_String_Builder *sb, char c, usize n) {
	std_da_reserve(sb->allocator, sb, sb->count + n + 1);
	for (usize i = 0; i < n; ++i) {
		*((sb->items + sb->count + i)) = c;
	}
	sb->count += n;
}

i32 std_sb_appendf(Std_String_Builder *sb, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	i32 n = vsnprintf(NULL, 0, fmt, args);
	va_end(args);

	std_da_reserve(sb->allocator, sb, sb->count + n + 1);
	char *dest = sb->items + sb->count;
	va_start(args, fmt);
	vsnprintf(dest, n+1, fmt, args);
	va_end(args);

	sb->count += n;

	return n;
}

static Std_RefStrings_Page *std_sp_new_refs_page(Std_StringPool *sp) {
	usize size = sizeof(Std_RefStrings_Page) + STRINGPOOL_DEFAULT_COUNT * sizeof(Std_RefString);
	Std_RefStrings_Page *page = std_allocz(sp->allocator, size);
	if (page == NULL) return NULL;
	page->count = STRINGPOOL_DEFAULT_COUNT;
	return page;
}

Std_RefString *std_sp_find_ref(Std_StringPool *sp, Std_String str) {
	for (Std_RefStrings_Page *page = sp->refs.first; page != NULL; page = page->next) {
		for (usize i = 0; i < page->count; ++i) {
			Std_RefString *ref = &page->items[i];
			if (ref->count > 0 && std_str_eq(ref->str, str)) {
			    return ref;
			}
		}
	}

	return NULL;
}

Std_RefString *std_sp_find_free(Std_StringPool *sp) {
	for (Std_RefStrings_Page *page = sp->refs.first; page != NULL; page = page->next) {
		for (usize i = 0; i < page->count; ++i) {
			if (page->items[i].count == 0) return &page->items[i];
		}
	}

	return NULL;
}

bool std_sp_alloc_string(Std_StringPool *sp, Std_String str, Std_RefString **ref_str) {
	if (ref_str == NULL) {
		return false;
	}

	if (sp->refs.first == NULL) {
		sp->refs.first = std_sp_new_refs_page(sp);
		if (sp->refs.first == NULL) return false;
		sp->refs.last = sp->refs.first;
	}

	if (sp->buf == NULL) {
		sp->buf = std_allocz(sp->allocator, STRINGPOOL_DEFAULT_CAPACITY);
		if (sp->buf == NULL) {
			return false;
		}
		sp->buf_capacity = STRINGPOOL_DEFAULT_CAPACITY;
	} else if (sp->buf_capacity - sp->buf_offset < str.length) {
		std_sp_compact(sp);

		if (sp->buf_capacity - sp->buf_offset < str.length) {
			usize new_capacity = sp->buf_capacity * 2;
			while (new_capacity - sp->buf_offset < str.length) new_capacity *= 2;
			char *new_buf = std_alloc(sp->allocator, new_capacity);
			if (new_buf == NULL) return false;
			memcpy(new_buf, sp->buf, sp->buf_offset);
			ptrdiff_t delta = new_buf - sp->buf;
			for (Std_RefStrings_Page *page = sp->refs.first; page != NULL; page = page->next) {
				for (usize i = 0; i < page->count; ++i) {
					if (page->items[i].count > 0) page->items[i].str.str += delta;
				}
			}
			std_free(sp->allocator, sp->buf);
			sp->buf = new_buf;
			sp->buf_capacity = new_capacity;
		}
	}

	Std_RefString *ref = std_sp_find_ref(sp, str);
	if (ref != NULL) {
		ref->count++;
		*ref_str = ref;
		return true;
	}

	ref = std_sp_find_free(sp);
	if (ref == NULL) {
		Std_RefStrings_Page *new_page = std_sp_new_refs_page(sp);
		if (new_page == NULL) return false;
		sp->refs.last->next = new_page;
		sp->refs.last = new_page;
		ref = &new_page->items[0];
	}

	char *dest = sp->buf + sp->buf_offset;
	sp->buf_offset += str.length;
	memcpy(dest, str.str, str.length);

	ref->str = (Std_String){ .str = dest, .length = str.length };
	ref->count = 1;
	*ref_str = ref;
	return true;
}

void std_sp_compact(Std_StringPool *sp) {
	if (sp->buf == NULL || sp->refs.first == NULL || sp->buf_offset == 0) return;

	bool any_freed = false;
	for (Std_RefStrings_Page *page = sp->refs.first; page != NULL && !any_freed; page = page->next) {
		for (usize i = 0; i < page->count; ++i) {
			if (page->items[i].count == 0 && page->items[i].str.str != NULL) {
				any_freed = true;
				break;
			}
		}
	}
	if (!any_freed) return;

	char *write_ptr = sp->buf;

	for (;;) {
		Std_RefString *min_ref = NULL;
		for (Std_RefStrings_Page *page = sp->refs.first; page != NULL; page = page->next) {
			for (usize i = 0; i < page->count; ++i) {
				Std_RefString *ref = &page->items[i];
				if (ref->count == 0 || ref->str.str < write_ptr) continue;
				if (min_ref == NULL || ref->str.str < min_ref->str.str) min_ref = ref;
			}
		}

		if (min_ref == NULL) break;

		if (min_ref->str.str != write_ptr) {
			memmove(write_ptr, min_ref->str.str, min_ref->str.length);
			min_ref->str.str = write_ptr;
		}
		write_ptr += min_ref->str.length;
	}

	sp->buf_offset = (usize)(write_ptr - sp->buf);
}

#endif
