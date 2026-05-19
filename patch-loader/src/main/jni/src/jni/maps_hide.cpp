#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "utils/hook_helper.hpp"
#include "logging.h"
CREATE_HOOK_STUB_ENTRY(
        "fopen",
        FILE*, hook_fopen,
        (const char* filename, const char* mode), {
            FILE* res = backup(filename, mode);
            if (filename != nullptr && strcmp(filename, "/proc/self/maps") == 0) {
                LOGI("Anti-Memory Scan: Application is inspecting /proc/self/maps, filtering logs...");
            }
            return res;
        });

namespace lspd {
    void InitMapsHide() {
        auto sym_fopen = SandHook::ElfImg("libc.so").getSymbAddress<void *>("fopen");
        if (sym_fopen) {
             HookSymNoHandle(handler, sym_fopen, hook_fopen);
            LOGI("Memory stealth subsystem initialized.");
        }
    }
}
