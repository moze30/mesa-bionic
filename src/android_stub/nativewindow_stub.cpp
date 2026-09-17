#include <vndk/window.h>
#include <vndk/hardware_buffer.h>
#include <android/log.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <link.h>
#include <elf.h>
#include <limits.h>

/* The Android loader ignores LD_LIBRARY_PATH, so the ICD cannot rely on a
 * libnativewindow.so shipped next to it: the system one gets picked instead,
 * and on devices where it cannot be loaded the whole ICD is dropped.  Provide
 * the AHardwareBuffer entry points in the ICD itself and forward them to the
 * platform libandroid.so, which exposes the full gralloc-backed API including
 * AHardwareBuffer_getNativeHandle. */

namespace {

void *lookup(const char *name);

/* The rootfs puts its own libraries ahead of /system in LD_LIBRARY_PATH, so
 * the platform libandroid.so binds its dependencies to rootfs stubs that lack
 * the required symbols (binder_ndk first, then libEGL via libgui).  Walk the
 * real dependency tree from /system, deepest first, and load it before
 * libandroid.so itself. */

const char *const kSearchDirs[] = {
   "/system/lib64",
   "/system/system_ext/lib64",
   "/vendor/lib64",
   "/vendor/lib64/egl",
};
constexpr int kNumSearchDirs = sizeof(kSearchDirs) / sizeof(kSearchDirs[0]);

constexpr int kMaxNeeded = 96;
constexpr int kMaxName = 160;
constexpr int kMaxVisited = 128;

char g_visited[kMaxVisited][kMaxName];
int g_num_visited = 0;

bool
visited(const char *soname)
{
   for (int i = 0; i < g_num_visited; i++)
      if (strcmp(g_visited[i], soname) == 0)
         return true;
   return false;
}

void
mark_visited(const char *soname)
{
   if (g_num_visited < kMaxVisited) {
      snprintf(g_visited[g_num_visited], kMaxName, "%s", soname);
      g_num_visited++;
   }
}

/* Reads the DT_NEEDED sonames of an ELF file without mapping it. */
bool
read_needed(const char *path, char names[][kMaxName], int *count)
{
   *count = 0;

   FILE *f = fopen(path, "rb");
   if (f == nullptr)
      return false;

   Elf64_Ehdr eh;
   if (fread(&eh, sizeof(eh), 1, f) != 1 ||
       memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
       eh.e_ident[EI_CLASS] != ELFCLASS64) {
      fclose(f);
      return false;
   }

   Elf64_Phdr *ph = (Elf64_Phdr *)calloc(eh.e_phnum, sizeof(Elf64_Phdr));
   if (ph == nullptr) {
      fclose(f);
      return false;
   }
   fseeko(f, eh.e_phoff, SEEK_SET);
   if (fread(ph, sizeof(Elf64_Phdr), eh.e_phnum, f) != eh.e_phnum) {
      free(ph);
      fclose(f);
      return false;
   }

   const Elf64_Phdr *dyn_ph = nullptr;
   for (int i = 0; i < eh.e_phnum; i++) {
      if (ph[i].p_type == PT_DYNAMIC)
         dyn_ph = &ph[i];
   }
   if (dyn_ph == nullptr) {
      free(ph);
      fclose(f);
      return false;
   }

   Elf64_Dyn *dyn = (Elf64_Dyn *)calloc(1, dyn_ph->p_filesz);
   if (dyn == nullptr) {
      free(ph);
      fclose(f);
      return false;
   }
   fseeko(f, dyn_ph->p_offset, SEEK_SET);
   if (fread(dyn, dyn_ph->p_filesz, 1, f) != 1) {
      free(dyn);
      free(ph);
      fclose(f);
      return false;
   }

   uint64_t strtab_va = 0;
   for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
      if (d->d_tag == DT_STRTAB)
         strtab_va = d->d_un.d_ptr;
   }

   long strtab_off = -1;
   for (int i = 0; i < eh.e_phnum && strtab_va != 0; i++) {
      if (ph[i].p_type != PT_LOAD)
         continue;
      if (strtab_va >= ph[i].p_vaddr &&
          strtab_va < ph[i].p_vaddr + ph[i].p_filesz) {
         strtab_off = ph[i].p_offset + (strtab_va - ph[i].p_vaddr);
         break;
      }
   }

   if (strtab_off >= 0) {
      for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL && *count < kMaxNeeded; d++) {
         if (d->d_tag != DT_NEEDED)
            continue;
         fseeko(f, strtab_off + d->d_un.d_val, SEEK_SET);
         char buf[kMaxName] = "";
         size_t n = fread(buf, 1, kMaxName - 1, f);
         buf[n] = '\0';
         snprintf(names[*count], kMaxName, "%s", buf);
         (*count)++;
      }
   }

   free(dyn);
   free(ph);
   fclose(f);
   return true;
}

void
preload_chain(const char *soname, int depth)
{
   if (depth > 6 || visited(soname))
      return;
   mark_visited(soname);

   char path[PATH_MAX] = "";
   for (int i = 0; i < kNumSearchDirs; i++) {
      char cand[PATH_MAX];
      snprintf(cand, sizeof(cand), "%s/%s", kSearchDirs[i], soname);
      if (access(cand, R_OK) == 0) {
         snprintf(path, sizeof(path), "%s", cand);
         break;
      }
   }

   if (path[0] == '\0') {
      fprintf(stderr, "WL-AHB-STUB: dep %-28s not found in system dirs\n",
              soname);
      return;
   }

   char needed[kMaxNeeded][kMaxName];
   int n = 0;
   if (read_needed(path, needed, &n)) {
      for (int i = 0; i < n; i++)
         preload_chain(needed[i], depth + 1);
   }

   void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
   fprintf(stderr, "WL-AHB-STUB: dep %-28s -> %p (%s)\n", soname, h,
           h != nullptr ? "ok" : dlerror());
}

int
phdr_dump_cb(struct dl_phdr_info *info, size_t size, void *data)
{
   (void)size;
   (void)data;
   fprintf(stderr, "WL-AHB-STUB: mod base=%p name=%s\n",
           (void *)info->dlpi_addr,
           info->dlpi_name != nullptr ? info->dlpi_name : "(null)");
   return 0;
}

void
dump_loaded_modules(void)
{
   fprintf(stderr, "WL-AHB-STUB: === loaded modules ===\n");
   dl_iterate_phdr(phdr_dump_cb, nullptr);
}

void
preload_platform_deps(void)
{
   static bool done = false;

   if (done)
      return;
   done = true;

   dump_loaded_modules();

   char needed[kMaxNeeded][kMaxName];
   int n = 0;
   if (read_needed("/system/lib64/libandroid.so", needed, &n)) {
      fprintf(stderr, "WL-AHB-STUB: libandroid.so needs %d libs\n", n);
      for (int i = 0; i < n; i++) {
         fprintf(stderr, "WL-AHB-STUB: need %s\n", needed[i]);
         preload_chain(needed[i], 0);
      }
   } else {
      fprintf(stderr,
              "WL-AHB-STUB: cannot read deps of /system/lib64/libandroid.so\n");
   }

   void *h = dlopen("/system/lib64/libandroid.so", RTLD_NOW | RTLD_GLOBAL);
   fprintf(stderr, "WL-AHB-STUB: post-preload /system/lib64/libandroid.so -> "
                   "%p (%s)\n",
           h, h != nullptr ? "ok" : dlerror());
}

const char *const kLibCandidates[] = {
   "/apex/com.android.runtime/lib64/libandroid.so",
   "/system/lib64/libandroid.so",
   "/system/system_ext/lib64/libandroid.so",
   "libandroid.so",
};
constexpr int kNumLibCandidates =
   sizeof(kLibCandidates) / sizeof(kLibCandidates[0]);

void *
candidate(int i)
{
   static void *handles[kNumLibCandidates] = {};
   static bool resolved = false;

   if (!resolved) {
      fprintf(stderr,
              "WL-AHB-STUB: uid=%d LD_LIBRARY_PATH=%s LD_PRELOAD=%s "
              "ANDROID_ROOT=%s\n",
              getuid(), getenv("LD_LIBRARY_PATH"), getenv("LD_PRELOAD"),
              getenv("ANDROID_ROOT"));
      fprintf(stderr,
              "WL-AHB-STUB: access /system=%d /system/lib64=%d /apex=%d "
              "/linkerconfig/ld.config.txt=%d /system/etc/ld.config.txt=%d "
              "/system/lib64/libandroid.so=%d\n",
              access("/system", X_OK), access("/system/lib64", X_OK),
              access("/apex", X_OK), access("/linkerconfig/ld.config.txt", R_OK),
              access("/system/etc/ld.config.txt", R_OK),
              access("/system/lib64/libandroid.so", R_OK));
      for (int j = 0; j < kNumLibCandidates; j++) {
         handles[j] = dlopen(kLibCandidates[j], RTLD_NOW | RTLD_GLOBAL);
         if (handles[j] != nullptr) {
            fprintf(stderr, "WL-AHB-STUB: backend %s\n", kLibCandidates[j]);
            break;
         }
         fprintf(stderr, "WL-AHB-STUB: dlopen %s failed: access=%d err=%s\n",
                 kLibCandidates[j], access(kLibCandidates[j], R_OK),
                 dlerror());
      }
      if (handles[0] == nullptr && handles[1] == nullptr &&
          handles[2] == nullptr && handles[3] == nullptr) {
         fprintf(stderr, "WL-AHB-STUB: no libandroid.so found\n");
      }
      resolved = true;
   }
   return handles[i];
}

/* The rootfs ships a termux shim named libandroid.so that lacks
 * AHardwareBuffer_getNativeHandle but can open the platform library in its
 * own namespace.  Route around the shim through that namespace.
 *
 * The absolute path matters: the bare name resolves through LD_LIBRARY_PATH
 * back to the shim, while the namespace's own path list (/system/lib64) is
 * what lets libandroid.so pick the real libbinder_ndk.so over the rootfs
 * stub. */
void *
platform_android(void)
{
   static void *h = nullptr;
   static bool resolved = false;

   if (!resolved) {
      resolved = true;
      preload_platform_deps();

      void *direct = dlopen("/system/lib64/libandroid.so", RTLD_NOW | RTLD_GLOBAL);
      fprintf(stderr,
              "WL-AHB-STUB: direct /system/lib64/libandroid.so -> %p (%s) "
              "getNativeHandle=%p\n",
              direct, direct != nullptr ? "ok" : dlerror(),
              direct != nullptr
                 ? dlsym(direct, "AHardwareBuffer_getNativeHandle")
                 : nullptr);
      if (direct != nullptr) {
         h = direct;
         return h;
      }

      void *ns = dlopen("libtermux-platform-ns.so", RTLD_NOW | RTLD_GLOBAL);
      if (ns == nullptr) {
         fprintf(stderr, "WL-AHB-STUB: libtermux-platform-ns.so unavailable\n");
         return nullptr;
      }
      typedef void *(*platform_dlopen_t)(const char *, int);
      platform_dlopen_t pdl =
         reinterpret_cast<platform_dlopen_t>(dlsym(ns, "platform_dlopen"));
      if (pdl == nullptr) {
         fprintf(stderr, "WL-AHB-STUB: platform_dlopen unavailable\n");
         return nullptr;
      }
      h = pdl("/system/lib64/libandroid.so", RTLD_NOW | RTLD_GLOBAL);
      void *sym = h != nullptr ? dlsym(h, "AHardwareBuffer_getNativeHandle")
                               : nullptr;
      fprintf(stderr,
              "WL-AHB-STUB: platform namespace /system/lib64/libandroid.so -> "
              "%p getNativeHandle=%p err=%s\n",
              h, sym, h != nullptr ? "-" : dlerror());
   }
   return h;
}

/* The platform library is loaded in this process even when it cannot be
 * reached through the rootfs shim's exported symbols.  Resolve a missing
 * symbol straight from the dynamic symbol table of every loaded module whose
 * name starts with "libandroid", adding the module load bias as bionic does. */

uint32_t
gnu_hash(const char *s)
{
   uint32_t h = 5381;
   for (; *s; s++)
      h = (h << 5) + h + (uint8_t)*s;
   return h;
}

void *
symbol_in_object(ElfW(Addr) base, const ElfW(Phdr) * phdr, int phnum,
                 const char *name)
{
   const ElfW(Dyn) *dyn = nullptr;
   for (int i = 0; i < phnum; i++) {
      if (phdr[i].p_type == PT_DYNAMIC) {
         dyn = reinterpret_cast<const ElfW(Dyn) *>(base + phdr[i].p_vaddr);
         break;
      }
   }
   if (dyn == nullptr)
      return nullptr;

   const ElfW(Sym) *symtab = nullptr;
   const char *strtab = nullptr;
   const uint32_t *gnu = nullptr;
   const uint32_t *sysv = nullptr;
   for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
      switch (d->d_tag) {
      case DT_SYMTAB:
         symtab = reinterpret_cast<const ElfW(Sym) *>(base + d->d_un.d_ptr);
         break;
      case DT_STRTAB:
         strtab = reinterpret_cast<const char *>(base + d->d_un.d_ptr);
         break;
      case DT_GNU_HASH:
         gnu = reinterpret_cast<const uint32_t *>(base + d->d_un.d_ptr);
         break;
      case DT_HASH:
         sysv = reinterpret_cast<const uint32_t *>(base + d->d_un.d_ptr);
         break;
      }
   }
   if (symtab == nullptr || strtab == nullptr)
      return nullptr;

   if (gnu != nullptr) {
      const uint32_t nbuckets = gnu[0];
      const uint32_t symoffset = gnu[1];
      const uint32_t bloom_size = gnu[2];
      const uint32_t *buckets =
         &gnu[4 + (bloom_size * sizeof(ElfW(Addr)) / sizeof(uint32_t))];
      const uint32_t *chain = &buckets[nbuckets];
      const uint32_t h = gnu_hash(name);
      uint32_t n = buckets[h % nbuckets];
      if (n < symoffset)
         return nullptr;
      for (;;) {
         const uint32_t hv = chain[n - symoffset];
         if ((hv | 1) == (h | 1) &&
             strcmp(strtab + symtab[n].st_name, name) == 0)
            return reinterpret_cast<void *>(base + symtab[n].st_value);
         if (hv & 1)
            break;
         n++;
      }
      return nullptr;
   }

   if (sysv != nullptr) {
      const uint32_t nchain = sysv[1];
      for (uint32_t i = 1; i < nchain; i++) {
         if (symtab[i].st_name != 0 &&
             strcmp(strtab + symtab[i].st_name, name) == 0)
            return reinterpret_cast<void *>(base + symtab[i].st_value);
      }
   }
   return nullptr;
}

struct Search {
   const char *symbol;
   void *addr;
};

int
phdr_cb(struct dl_phdr_info *info, size_t size, void *data)
{
   Search *search = reinterpret_cast<Search *>(data);
   if (search->addr != nullptr)
      return 0;

   const char *path = info->dlpi_name;
   if (path == nullptr || path[0] == '\0')
      return 0;
   const char *base = strrchr(path, '/');
   base = base != nullptr ? base + 1 : path;
   if (strncmp(base, "libandroid", 10) != 0)
      return 0;

   void *addr = symbol_in_object(info->dlpi_addr, info->dlpi_phdr,
                                 info->dlpi_phnum, search->symbol);
   fprintf(stderr, "WL-AHB-STUB: loaded %s -> %s=%p\n", path, search->symbol,
           addr);
   if (addr != nullptr) {
      search->addr = addr;
      return 1;
   }
   return 0;
}

void *
symbol_from_loaded(const char *name)
{
   Search search = { name, nullptr };
   dl_iterate_phdr(phdr_cb, &search);
   return search.addr;
}

void *
lookup(const char *name)
{
   static bool warned = false;

   /* Prefer the real platform library: the rootfs shim found through the bare
    * name only has trampolines whose jump table is never populated, so calling
    * through it silently returns without doing anything. */
   void *ph = platform_android();
   if (ph != nullptr) {
      void *ps = dlsym(ph, name);
      if (ps != nullptr) {
         fprintf(stderr, "WL-AHB-STUB: %s from platform namespace\n", name);
         return ps;
      }
   }

   for (int i = 0; i < kNumLibCandidates; i++) {
      void *h = candidate(i);
      if (h == nullptr)
         continue;
      void *s = dlsym(h, name);
      if (s != nullptr) {
         fprintf(stderr, "WL-AHB-STUB: %s from %s\n", name, kLibCandidates[i]);
         return s;
      }
   }

   void *s = symbol_from_loaded(name);
   if (s != nullptr) {
      fprintf(stderr, "WL-AHB-STUB: %s from loaded module\n", name);
      return s;
   }

   if (!warned) {
      warned = true;
      fprintf(stderr, "WL-AHB-STUB: symbol %s unavailable\n", name);
      __android_log_print(ANDROID_LOG_ERROR, "WinFusion",
                          "AHardwareBuffer symbol %s unavailable", name);
   }
   return nullptr;
}

template <typename T>
static T
sym(const char *name)
{
   return reinterpret_cast<T>(lookup(name));
}

}

extern "C" {

AHardwareBuffer *
ANativeWindowBuffer_getHardwareBuffer(ANativeWindowBuffer *anwb)
{
   typedef AHardwareBuffer *(*fn_t)(ANativeWindowBuffer *);
   static fn_t fn = sym<fn_t>("ANativeWindowBuffer_getHardwareBuffer");
   return fn != nullptr ? fn(anwb) : nullptr;
}

void
AHardwareBuffer_acquire(AHardwareBuffer *buffer)
{
   typedef void (*fn_t)(AHardwareBuffer *);
   static fn_t fn = sym<fn_t>("AHardwareBuffer_acquire");
   if (fn != nullptr)
      fn(buffer);
}

void
AHardwareBuffer_release(AHardwareBuffer *buffer)
{
   typedef void (*fn_t)(AHardwareBuffer *);
   static fn_t fn = sym<fn_t>("AHardwareBuffer_release");
   if (fn != nullptr)
      fn(buffer);
}

void
AHardwareBuffer_describe(const AHardwareBuffer *buffer,
                         AHardwareBuffer_Desc *outDesc)
{
   typedef void (*fn_t)(const AHardwareBuffer *, AHardwareBuffer_Desc *);
   static fn_t fn = sym<fn_t>("AHardwareBuffer_describe");
   if (fn != nullptr)
      fn(buffer, outDesc);
}

int
AHardwareBuffer_allocate(const AHardwareBuffer_Desc *desc,
                         AHardwareBuffer **outBuffer)
{
   typedef int (*fn_t)(const AHardwareBuffer_Desc *, AHardwareBuffer **);
   static fn_t fn = sym<fn_t>("AHardwareBuffer_allocate");
   return fn != nullptr ? fn(desc, outBuffer) : -1;
}

int
AHardwareBuffer_isSupported(const AHardwareBuffer_Desc *desc)
{
   typedef int (*fn_t)(const AHardwareBuffer_Desc *);
   static fn_t fn = sym<fn_t>("AHardwareBuffer_isSupported");
   return fn != nullptr ? fn(desc) : 0;
}

int
AHardwareBuffer_sendHandleToUnixSocket(const AHardwareBuffer *buffer,
                                       int socket_fd)
{
   typedef int (*fn_t)(const AHardwareBuffer *, int);
   static fn_t fn = sym<fn_t>("AHardwareBuffer_sendHandleToUnixSocket");
   return fn != nullptr ? fn(buffer, socket_fd) : -1;
}

int
AHardwareBuffer_recvHandleFromUnixSocket(int socket_fd,
                                         AHardwareBuffer **outBuffer)
{
   typedef int (*fn_t)(int, AHardwareBuffer **);
   static fn_t fn = sym<fn_t>("AHardwareBuffer_recvHandleFromUnixSocket");
   return fn != nullptr ? fn(socket_fd, outBuffer) : -1;
}

const native_handle_t *
AHardwareBuffer_getNativeHandle(const AHardwareBuffer *buffer)
{
   typedef const native_handle_t *(*fn_t)(const AHardwareBuffer *);
   static fn_t fn = sym<fn_t>("AHardwareBuffer_getNativeHandle");
   return fn != nullptr ? fn(buffer) : nullptr;
}

void
ANativeWindow_acquire(ANativeWindow *window)
{
}

void
ANativeWindow_release(ANativeWindow *window)
{
}

int32_t
ANativeWindow_getFormat(ANativeWindow *window)
{
   return 0;
}

int
ANativeWindow_setSwapInterval(ANativeWindow *window, int interval)
{
   return 0;
}

int
ANativeWindow_query(const ANativeWindow *window,
                    ANativeWindowQuery query,
                    int *value)
{
   return 0;
}

int
ANativeWindow_dequeueBuffer(ANativeWindow *window,
                            ANativeWindowBuffer **buffer,
                            int *fenceFd)
{
   return 0;
}

int
ANativeWindow_queueBuffer(ANativeWindow *window,
                          ANativeWindowBuffer *buffer,
                          int fenceFd)
{
   return 0;
}

int
ANativeWindow_cancelBuffer(ANativeWindow *window,
                           ANativeWindowBuffer *buffer,
                           int fenceFd)
{
   return 0;
}

int
ANativeWindow_setUsage(ANativeWindow *window, uint64_t usage)
{
   return 0;
}

int
ANativeWindow_setSharedBufferMode(ANativeWindow *window,
                                  bool sharedBufferMode)
{
   return 0;
}
}
