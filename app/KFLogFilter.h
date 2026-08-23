//
//  KFLogFilter.h
//  Kernel log filter — extracts readable, representative short lines
//

#ifndef KFLOG_FILTER_H
#define KFLOG_FILTER_H

#include <stdbool.h>
#include <stdint.h>

// Max lines to keep in ring buffer
#define KFLOG_MAX_LINES     200
#define KFLOG_LINE_MAX      256

typedef struct {
    char timestamp[6];      // "--:--" + null
    char tag[16];           // e.g. "[MEM]", "[SBX]"
    char text[128];         // short readable sentence
    int isRed;              // 1 = red text, 0 = normal white
} KFLogLine;

// Initialize filter and locate kernel msgbuf
typedef struct {
    uint64_t msgbuf_addr;   // kernel msgbuf virtual address
    uint64_t msgbuf_size;   // size of ring buffer
    uint64_t read_offset;   // last read position
    KFLogLine lines[KFLOG_MAX_LINES];
    int line_count;
    int line_head;          // ring buffer head
} KFLogFilter;

bool KFLogInitFilter(KFLogFilter *filter);

// Poll msgbuf for new lines, return number of new lines found
int KFLogPoll(KFLogFilter *filter);

// Get a line by index (0 = newest)
const KFLogLine* KFLogGetLine(KFLogFilter *filter, int index);

#endif
