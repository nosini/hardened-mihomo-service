#include <pthread.h>
#include <stdlib.h>
static void *thread(void *arg) { return arg; }
__attribute__((constructor)) static void make_thread(void) {
 pthread_t id;
 if (pthread_create(&id, 0, thread, 0) || pthread_join(id, 0)) abort();
}
