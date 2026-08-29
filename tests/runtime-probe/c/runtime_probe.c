#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>
#include <troe/runtime.h>

/* Force a large executable payload that cannot be staged in the kernel heap. */
static const unsigned char troe_large_kex_payload[8U * 1024U * 1024U] = {
    [0] = 0x54, [8U * 1024U * 1024U - 1U] = 0x45};

static int fail(const char *stage) {
  fprintf(stderr, "c-runtime-probe: %s failed (errno=%d)\n", stage, errno);
  return 1;
}

static int compare_ints(const void *left, const void *right) {
  int a = *(const int *)left;
  int b = *(const int *)right;
  return (a > b) - (a < b);
}

int troe_c_missing_capability_probe(void) {
  static const struct troe_runtime_host host = {
      .abi = TROE_C_RUNTIME_ABI,
      .structure_bytes = sizeof(struct troe_runtime_host),
  };
  const struct troe_runtime_configuration configuration = {
      .host = &host,
      .cwd = "/",
  };
  if (troe_runtime_initialize(&configuration) != 0)
    return 1;
  unsigned char byte;
  struct timespec instant;
  int failed = 0;
  errno = 0;
  if (open("/tmp/ungranted", O_RDONLY) != -1 || errno != EACCES)
    failed = 1;
  errno = 0;
  if (getrandom(&byte, 1, 0) != -1 || errno != EACCES)
    failed = 1;
  errno = 0;
  if (clock_gettime(CLOCK_MONOTONIC, &instant) != -1 || errno != EACCES)
    failed = 1;
  errno = 0;
  if (mkdir("/tmp/ungranted", 0700) != -1 || errno != EACCES)
    failed = 1;
  troe_runtime_finalize();
  return failed;
}

int troe_c_runtime_probe(int argc, char **argv) {
  if (argc < 1 || argv == NULL || argv[0] == NULL || getenv("PATH") == NULL)
    return fail("argv/environment");
  if (troe_large_kex_payload[0] != 0x54 ||
      troe_large_kex_payload[sizeof(troe_large_kex_payload) - 1] != 0x45)
    return fail("large image payload");

  unsigned char *large = calloc(1, 2U * 1024U * 1024U);
  if (large == NULL || large[0] != 0 || large[2U * 1024U * 1024U - 1] != 0)
    return fail("large calloc");
  large[0] = 0x11;
  large[2U * 1024U * 1024U - 1] = 0x22;
  unsigned char *grown = realloc(large, 3U * 1024U * 1024U);
  if (grown == NULL || grown[0] != 0x11 ||
      grown[2U * 1024U * 1024U - 1] != 0x22)
    return fail("large realloc");
  free(grown);
  void *aligned = NULL;
  if (posix_memalign(&aligned, 4096, 8192) != 0 ||
      ((uintptr_t)aligned & 4095U) != 0)
    return fail("aligned allocation");
  free(aligned);

  int values[] = {4, 1, 3, 2};
  qsort(values, 4, sizeof(values[0]), compare_ints);
  int wanted = 3;
  if (values[0] != 1 ||
      bsearch(&wanted, values, 4, sizeof(values[0]), compare_ints) == NULL)
    return fail("C algorithms");
  int scanned_decimal = 0;
  unsigned int scanned_hex = 0;
  double scanned_float = 0.0;
  if (sscanf("17 ff 2.5", "%d %x %lf", &scanned_decimal, &scanned_hex,
             &scanned_float) != 3 ||
      scanned_decimal != 17 || scanned_hex != 255 || scanned_float != 2.5)
    return fail("bounded scanning");

  mbstate_t state = {0};
  wchar_t character = 0;
  if (mbrtowc(&character, "\xce\xbb", 2, &state) != 2 || character != 0x03bb)
    return fail("UTF-8 decode");
  char encoded[4];
  if (wcrtomb(encoded, character, &state) != 2 ||
      memcmp(encoded, "\xce\xbb", 2) != 0)
    return fail("UTF-8 encode");
  if (strcmp(setlocale(LC_ALL, NULL), "C") != 0 ||
      setlocale(LC_ALL, "uk_UA.UTF-8") != NULL)
    return fail("C locale");

  jmp_buf jump;
  int jumped = setjmp(jump);
  if (jumped == 0)
    longjmp(jump, 7);
  if (jumped != 7)
    return fail("setjmp");

  pthread_t thread;
  if (pthread_create(&thread, NULL, NULL, NULL) != ENOTSUP)
    return fail("thread unsupported");
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  if (pthread_mutex_lock(&mutex) != 0 || pthread_mutex_unlock(&mutex) != 0)
    return fail("single-thread lock");
  pthread_key_t key;
  if (pthread_key_create(&key, NULL) != 0 ||
      pthread_setspecific(key, (void *)(uintptr_t)0x1234) != 0 ||
      pthread_getspecific(key) != (void *)(uintptr_t)0x1234 ||
      pthread_key_delete(key) != 0)
    return fail("thread-specific storage");

  struct timespec monotonic;
  time_t wall = time(NULL);
  struct tm calendar;
  char formatted[32];
  if (wall < 0 || clock_gettime(CLOCK_MONOTONIC, &monotonic) != 0 ||
      gmtime_r(&wall, &calendar) == NULL ||
      strftime(formatted, sizeof(formatted), "%Y-%m-%d", &calendar) != 10)
    return fail("time");
  unsigned char random_bytes[64];
  if (getrandom(random_bytes, sizeof(random_bytes), 0) !=
          (ssize_t)sizeof(random_bytes) ||
      memcmp(random_bytes, random_bytes + 32, 32) == 0)
    return fail("randomness");

  const char *directory_path = "/vol/root/c-runtime-probe";
  const char *file_path = "/vol/root/c-runtime-probe/data.txt";
  (void)remove(file_path);
  (void)rmdir(directory_path);
  if (mkdir(directory_path, 0700) != 0)
    return fail("mkdir");
  if (chdir(directory_path) != 0)
    return fail("chdir");
  char cwd[256];
  if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, directory_path) != 0)
    return fail("getcwd");
  FILE *file = fopen("data.txt", "w");
  if (file == NULL || fprintf(file, "runtime-%d-%s", 42, "ok") != 13 ||
      fclose(file) != 0)
    return fail("stdio write");
  file = fopen("data.txt", "a");
  if (file == NULL || fputs("+append", file) < 0 || fclose(file) != 0)
    return fail("stdio append");
  file = fopen("data.txt", "r");
  char content[32] = {0};
  if (file == NULL || fread(content, 1, 20, file) != 20 ||
      strcmp(content, "runtime-42-ok+append") != 0 ||
      fseek(file, -2, SEEK_END) != 0 || fgetc(file) != 'n' ||
      fclose(file) != 0)
    return fail("stdio read/seek");
  struct stat metadata;
  if (stat("data.txt", &metadata) != 0 || metadata.st_size != 20)
    return fail("metadata");
  int directory_descriptor = open(".", O_RDONLY | O_DIRECTORY);
  if (directory_descriptor < 0 ||
      fstat(directory_descriptor, &metadata) != 0 ||
      !S_ISDIR(metadata.st_mode) || close(directory_descriptor) != 0)
    return fail("directory descriptor");
  DIR *directory = opendir(".");
  int found = 0;
  if (directory == NULL)
    return fail("opendir");
  for (struct dirent *entry = readdir(directory); entry != NULL;
       entry = readdir(directory)) {
    if (strcmp(entry->d_name, "data.txt") == 0)
      found = 1;
  }
  if (!found || closedir(directory) != 0)
    return fail("readdir");
  if (rename("data.txt", "renamed.txt") != 0 ||
      link("renamed.txt", "linked.txt") != 0 ||
      symlink("renamed.txt", "symbolic.txt") != 0)
    return fail("link operations");
  char target[32];
  ssize_t target_length = readlink("symbolic.txt", target, sizeof(target));
  if (target_length != 11 || memcmp(target, "renamed.txt", 11) != 0)
    return fail("readlink");
  if (unlink("symbolic.txt") != 0 || unlink("linked.txt") != 0 ||
      unlink("renamed.txt") != 0 || chdir("/") != 0 || rmdir(directory_path) != 0)
    return fail("filesystem cleanup");

  if (system("true") != -1 || errno != ENOTSUP ||
      open("/tmp/unsupported", O_RDWR | O_CREAT, 0600) != -1 ||
      errno != ENOTSUP)
    return fail("unsupported operations");
  printf("c-runtime-probe ok image=0x%lx wall=%ld monotonic=%ld\n",
         (unsigned long)(uintptr_t)troe_large_kex_payload, (long)wall,
         (long)monotonic.tv_sec);
  return 0;
}
