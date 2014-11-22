
#ifndef COMMON_H
#define COMMON_H

#ifndef alignof
# define alignof(type)		offsetof(struct { char c; type t; },t)
#endif

#if !defined(__STDC__) || (__STDC_VERSION__ - 0) < 199901L
# define inline
#endif

#ifdef __GNUC__
# define likely(x)			__builtin_expect(!!(x), 1)
# define unlikely(x)			__builtin_expect((x), 0)
# define func_deprecated		__attribute__((deprecated))
# define func_format(fmt_n,arg_n)	__attribute__((format(printf,fmt_n,arg_n)))
# define func_va_null_terminated	__attribute__((sentinel(0)))
#else
# define likely(x)			!!(x)
# define unlikely(x)			(x)
# define func_deprecated
# define func_format(fmt_n,arg_n)
# define func_va_null_terminated
#endif

#define ARRAY_SIZE(...)		(sizeof(__VA_ARGS__)/sizeof(*(__VA_ARGS__)))
#define MIN(a,b)		((a) < (b) ? (a) : (b))
#define MAX(a,b)		((a) > (b) ? (a) : (b))
#define STR(x)			#x
#define XSTR(x)			STR(x)

#ifndef NDEBUG
# define DBG(...)		do { fprintf(stderr, "%9s:%-4d ", __FILE__, __LINE__); \
				     fprintf(stderr, __VA_ARGS__); } while (0)
# define LOG(...)		DBG(__VA_ARGS__)
#else
# define DBG(...)
# define LOG(...)		fprintf(stderr, __VA_ARGS__)
#endif
#define FATAL_DO(ret,...)	do { {__VA_ARGS__;} exit(ret); } while (0)
#define FATAL(ret,...)		FATAL_DO(ret,LOG(__VA_ARGS__))

#include <sys/types.h>		/* ssize_t */
#include <stdlib.h>		/* malloc(), etc. */
#include <stdio.h>		/* *printf() */
#include <string.h>		/* strerror() */
#include <errno.h>		/* errno */

struct cstr {
	const char *s;
	size_t l;
};

#define CSTR(x)			{ (x), sizeof(x)-1, }

static inline ssize_t ck_bsearch(
	const void *key, const void *base, size_t nmemb, size_t esz,
	int (*compar)(const void *, const void *)
) {
	ssize_t l = 0, r = (ssize_t)nmemb - 1, m;
	int c;
	while (l <= r) {
		m = l + (r-l)/2;
		c = compar(key, (const char *)base + m * esz);
		if (c < 0)
			r = m - 1;
		else if (c > 0)
			l = m + 1;
		else
			return m;
	}
	return ~l;
}

inline static void * ck_malloc(size_t size)
{
	void *p = malloc(size);
	if (size && unlikely(!p))
		FATAL(-1, "malloc: %s", strerror(errno));
	return p;
}

inline static void * ck_calloc(size_t nmemb, size_t size)
{
	void *p = calloc(nmemb, size);
	if (nmemb && size && unlikely(!p))
		FATAL(-1, "calloc: %s", strerror(errno));
	return p;
}

inline static void * ck_realloc(void *old_p, size_t size)
{
	void *p = realloc(old_p, size);
	if (size && unlikely(!p)) {
		free(old_p);
		FATAL(-1, "realloc: %s", strerror(errno));
	}
	return p;
}

inline static void * ck_memcpy(void *restrict dest, const void *restrict src, size_t n)
{
	return (char *)memcpy(dest, src, n) + n;
}

inline static void * ck_memmove(void *dest, const void *src, size_t n)
{
	return (char *)memmove(dest, src, n) + n;
}

inline static char * ck_strddup(const char *from, const char *to)
{
	size_t len = to - from;
	char *c = ck_malloc(len + 1);
	*(char *)ck_memcpy(c, from, len) = '\0';
	return c;
}

static inline void * memdup(const void *src, size_t n)
{
	return memcpy(ck_malloc(n), src, n);
}

#endif
