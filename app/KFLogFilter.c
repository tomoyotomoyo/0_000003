//
//  KFLogFilter.c
//  Kernel msgbuf reader — filters human-readable keywords, formats short lines
//

#include "KFLogFilter.h"
#include "kexploit/krw.h"
#include "kexploit/kutils.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/sysctl.h>

#ifndef KERN_MSGBUF
#define KERN_MSGBUF 83
#endif

// Keywords we care about — maps to a tag and isRed flag
static struct {
    const char *keyword;
    const char *tag;
    int isRed;
} g_keywords[] = {
    {"pmap_enter",  "[MEM]", 0},
    {"pmap_remove", "[MEM]", 0},
    {"vm_fault",    "[MEM]", 0},
    {"vm_pageout",  "[MEM]", 0},
    {"vm_allocate", "[MEM]", 0},
    {"sandbox:",    "[SBX]", 1},
    {"Sandbox",     "[SBX]", 1},
    {"kext:",       "[KXT]", 0},
    {"com.apple.driver.", "[KXT]", 0},
    {"IOKit:",      "[IOK]", 0},
    {"AppleARMPE",  "[IOK]", 0},
    {"AppleA",      "[CPU]", 0},
    {"execve:",     "[EXE]", 0},
    {"fork",        "[EXE]", 0},
    {"exit",        "[EXE]", 0},
    {"syscall:",    "[SYS]", 0},
    {"cpu=",        "[CPU]", 0},
    {"thermal",     "[THR]", 0},
    {"wake",        "[PWR]", 0},
    {"sleep",       "[PWR]", 0},
    {"pmset",       "[PWR]", 0},
    {"panic",       "[ERR]", 1},
    {"BUG:",        "[ERR]", 1},
    {"assert",      "[ERR]", 1},
    {"failed",      "[ERR]", 1},
    {NULL, NULL, 0}
};

extern uint64_t g_msgbufp_addr;
extern uint64_t g_msgbuf_size;

static bool find_msgbuf(uint64_t *addr, uint64_t *size) {
    // XPF resolved _msgbufp / _msgbufsize symbols during init_xpf()
    if (g_msgbufp_addr != 0 && g_msgbuf_size != 0) {
        *addr = kread64(g_msgbufp_addr);
        *size = kread32(g_msgbuf_size);
        if (*addr != 0 && *size != 0) {
            return true;
        }
    }
    // Fallback: sysctl kern.msgbuf (may be restricted on iOS)
    int mib[2] = { CTL_KERN, KERN_MSGBUF };
    size_t sz = 0;
    if (sysctl(mib, 2, NULL, &sz, NULL, 0) == 0 && sz > 0) {
        *size = sz;
    }
    return false;
}

bool KFLogInitFilter(KFLogFilter *filter) {
    memset(filter, 0, sizeof(*filter));
    return find_msgbuf(&filter->msgbuf_addr, &filter->msgbuf_size);
}

static void format_line(const char *raw, KFLogLine *out) {
    memset(out, 0, sizeof(*out));
    out->isRed = 0;
    strncpy(out->tag, "[---]", sizeof(out->tag) - 1);

    const char *p = raw;
    if (*p == '[') {
        double ts = 0;
        if (sscanf(p, "[%lf]", &ts) == 1) {
            time_t t = (time_t)ts;
            struct tm *tm = localtime(&t);
            if (tm) {
                snprintf(out->timestamp, sizeof(out->timestamp), "%02d:%02d",
                         tm->tm_min, tm->tm_sec);
            }
            p = strchr(p, ']');
            if (p) p++;
            while (*p == ' ' || *p == '\t') p++;
        }
    }
    if (out->timestamp[0] == '\0') {
        strcpy(out->timestamp, "--:--");
    }
    for (int i = 0; g_keywords[i].keyword; i++) {
        if (strstr(raw, g_keywords[i].keyword)) {
            strncpy(out->tag, g_keywords[i].tag, sizeof(out->tag) - 1);
            out->isRed = g_keywords[i].isRed;
            break;
        }
    }
    const char *colon = strchr(p, ':');
    if (colon) {
        p = colon + 1;
        while (*p == ' ') p++;
    }
    int len = 0;
    while (*p && *p != '\n' && *p != '\r' && len < sizeof(out->text) - 1) {
        out->text[len++] = *p++;
    }
    out->text[len] = '\0';
    if (out->text[0] == '\0') {
        strncpy(out->text, raw, sizeof(out->text) - 1);
    }
}

int KFLogPoll(KFLogFilter *filter) {
    if (filter->msgbuf_addr == 0 || filter->msgbuf_size == 0) {
        return 0;
    }
    char buf[4096];
    uint64_t offset = filter->read_offset % filter->msgbuf_size;
    uint64_t to_read = sizeof(buf) - 1;
    if (offset + to_read > filter->msgbuf_size) {
        to_read = filter->msgbuf_size - offset;
    }
    kreadbuf(filter->msgbuf_addr + offset, buf, to_read);
    buf[to_read] = '\0';

    int new_lines = 0;
    char *line = buf;
    char *next;
    while ((next = strchr(line, '\n')) != NULL) {
        *next = '\0';
        if (strlen(line) > 10) {
            KFLogLine entry;
            format_line(line, &entry);
            if (strcmp(entry.tag, "[---]") != 0) {
                filter->lines[filter->line_head] = entry;
                filter->line_head = (filter->line_head + 1) % KFLOG_MAX_LINES;
                if (filter->line_count < KFLOG_MAX_LINES) {
                    filter->line_count++;
                }
                new_lines++;
            }
        }
        line = next + 1;
        filter->read_offset += strlen(line) + 1;
    }
    return new_lines;
}

const KFLogLine* KFLogGetLine(KFLogFilter *filter, int index) {
    if (index < 0 || index >= filter->line_count) return NULL;
    int pos = (filter->line_head - 1 - index + KFLOG_MAX_LINES) % KFLOG_MAX_LINES;
    return &filter->lines[pos];
}
