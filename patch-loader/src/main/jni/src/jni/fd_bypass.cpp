#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "utils/hook_helper.hpp"
#include "logging.h"


CREATE_HOOK_STUB_ENTRY(
        "fstat",
        int, hook_fstat,
        (int fd, struct stat* buf), {
            int res = backup(fd, buf);
            if (res == 0 && buf != nullptr) {
            }
            return res;
        });

namespace lspd {
    void InitFdFilesBypass() {
        auto sym_fstat = SandHook::ElfImg("libc.so").getSymbAddress<void *>("fstat");
        if (sym_fstat) {
            HookSymNoHandle(handler, sym_fstat, hook_fstat);
            LOGI("File Descriptor virtualization active.");
        }
    }
}
