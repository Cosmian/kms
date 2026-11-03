/*
 * LD_PRELOAD shim for the Crypt2Pay PKCS#11 tests: make inotify_init1() fail.
 *
 * libpkcs11c2p.so starts a "surveyKeyDb" thread on the first C_OpenSession. It watches the
 * token key directory (<ObjectsDirectory>/<slot>-<label>/) with inotify and, for every
 * created/deleted key file, walks the slot's in-memory object list calling
 * strcmp(file_name, object->file_name). The library itself creates and deletes those files in
 * C_GenerateKey*, C_UnwrapKey and C_DestroyObject, and it publishes an object to the list
 * before assigning its file name, so the watcher intermittently reads a NULL file name and
 * crashes with SIGSEGV in strcmp (observed with a single thread creating and destroying keys,
 * and almost always with several). The crash is inside the vendor library: nothing in the
 * caller's code or ordering can prevent it.
 *
 * The watcher only exists to pick up key files written by *other* processes sharing the
 * directory, which these single-process tests never do. When inotify_init1() fails the
 * library logs "inotify_init1 () failed" and carries on without the watcher; every other
 * PKCS#11 function is unaffected.
 */
#include <errno.h>

int inotify_init1(int flags)
{
    (void)flags;
    errno = ENOSYS;
    return -1;
}
