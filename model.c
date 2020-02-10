/*
 * This is a model as used by our Coverity Scan systems. It was also in use
 * back when we were on Coverity Prevent.
 *
 * https://scan.coverity.com/projects/freebsd/model_file
 * upload it via https://scan.coverity.com/projects/freebsd?tab=analysis_settings
 */

/* From <sys/malloc.h>. */
#define M_WAITOK 0x0002

/*
 * If M_WAIT_OK is set, malloc() will always return something meaningful.
 */
void *
malloc(unsigned long size, struct malloc_type *mtp, int flags)
{
	int has_memory;

	__coverity_negative_sink__(size);

	if (flags & M_WAITOK || has_memory)
		return __coverity_alloc__(size);

	return 0;
}

/*
 * Don't complain about leaking FDs in unit tests.
 */
static void
leak(int fd)
{
	__coverity_close__(fd);
}
