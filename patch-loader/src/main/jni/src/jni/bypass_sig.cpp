#include "bypass_sig.h"
#include "elf_util.h"
#include "logging.h"
#include "native_util.h"
#include "patch_loader.h"
#include "utils/hook_helper.hpp"
#include "utils/jni_helper.hpp"
#include <string>
#include <mutex>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <semaphore.h>
#include <dlfcn.h>
#include <sys/ptrace.h>

namespace lspd {
    
    std::mutex path_mutex;
    std::string apkPath;
    std::string redirectPath;

    // دالة تحقق ذكية: تتأكد من أن الاستدعاء قادم من مكتبات الحماية فقط
    bool isCallerFromSecurityLib(void* lr) {
        Dl_info info;
        if (dladdr(lr, &info) && info.dli_fname) {
            std::string name(info.dli_fname);
            // استهدف مكتبات الحماية المعروفة لببجي
            return (name.find("libanort.so") != std::string::npos || 
                    name.find("libtgpa.so") != std::string::npos);
        }
        return false;
    }

    // 1. كسر المزامنة الانتقائي (تعديل الـ Post إلى Wait فقط إذا كان الطلب من الحماية)
    CREATE_HOOK_STUB_ENTRY("sem_post", int, hook_sem_post, (sem_t* sem), {
        void* lr = __builtin_return_address(0);
        if (sem != nullptr && isCallerFromSecurityLib(lr)) {
            LOGI("Anti-Detection: sem_post intercepted from SecurityLib. Emulating freeze.");
            return sem_wait(sem);
        }
        return backup(sem);
    });

    // 2. حماية الـ Ptrace لمنع اكتشاف أدوات التصحيح
    CREATE_HOOK_STUB_ENTRY("ptrace", long, hook_ptrace, (int request, pid_t pid, void* addr, void* data), {
        if (request == PTRACE_TRACEME) return 0;
        return backup(request, pid, addr, data);
    });

    // 3. اعتراض الملفات وتوجيه المسارات
    CREATE_HOOK_STUB_ENTRY("__openat", int, __openat, (int fd, const char* pathname, int flag, int mode), {
        if (pathname != nullptr) {
            std::lock_guard<std::mutex> lock(path_mutex);
            if (!apkPath.empty() && std::string(pathname) == apkPath) {
                return backup(fd, redirectPath.c_str(), flag, mode);
            }
        }
        return backup(fd, pathname, flag, mode);
    });

    CREATE_HOOK_STUB_ENTRY("open", int, hook_open, (const char* pathname, int flags, mode_t mode), {
        if (pathname != nullptr) {
            std::lock_guard<std::mutex> lock(path_mutex);
            if (std::string(pathname) == "/proc/self/maps") {
                return backup("/data/local/tmp/clean_maps", flags, mode);
            }
            if (!apkPath.empty() && std::string(pathname) == apkPath) {
                return backup(redirectPath.c_str(), flags, mode);
            }
        }
        return backup(pathname, flags, mode);
    });

    CREATE_HOOK_STUB_ENTRY("fopen", FILE*, hook_fopen, (const char* filename, const char* mode), {
        if (filename != nullptr) {
            std::lock_guard<std::mutex> lock(path_mutex);
            if (std::string(filename) == "/proc/self/maps") {
                return backup("/data/local/tmp/clean_maps", mode);
            }
            if (!apkPath.empty() && std::string(filename) == apkPath) {
                return backup(redirectPath.c_str(), mode);
            }
        }
        return backup(filename, mode);
    });

    CREATE_HOOK_STUB_ENTRY("readlink", ssize_t, hook_readlink, (const char* pathname, char* buf, size_t bufsiz), {
        if (pathname != nullptr) {
            std::lock_guard<std::mutex> lock(path_mutex);
            if (!apkPath.empty() && (std::string(pathname) == "/proc/self/exe" || std::string(pathname) == apkPath)) {
                snprintf(buf, bufsiz, "%s", apkPath.c_str());
                return strlen(buf);
            }
        }
        return backup(pathname, buf, bufsiz);
    });

    LSP_DEF_NATIVE_METHOD(void, SigBypass, enableOpenatHook, jstring origApkPath, jstring cacheApkPath) {
        auto libc = SandHook::ElfImg("libc.so");
        
        HookSymNoHandle(handler, libc.getSymbAddress<void*>("sem_post"), hook_sem_post);
        HookSymNoHandle(handler, libc.getSymbAddress<void*>("ptrace"), hook_ptrace);
        HookSymNoHandle(handler, libc.getSymbAddress<void*>("__openat"), __openat);
        HookSymNoHandle(handler, libc.getSymbAddress<void*>("open"), hook_open);
        HookSymNoHandle(handler, libc.getSymbAddress<void*>("fopen"), hook_fopen);
        HookSymNoHandle(handler, libc.getSymbAddress<void*>("readlink"), hook_readlink);

        {
            std::lock_guard<std::mutex> lock(path_mutex);
            lsplant::JUTFString str1(env, origApkPath);
            lsplant::JUTFString str2(env, cacheApkPath);
            apkPath = str1.get();
            redirectPath = str2.get();
        }
        LOGI("Native Integrity & Synchronization Emulation Matrix Fully Armed.");
    }

    static JNINativeMethod gMethods[] = {
            LSP_NATIVE_METHOD(SigBypass, enableOpenatHook, "(Ljava/lang/String;Ljava/lang/String;)V")
    };

    void RegisterBypass(JNIEnv* env) {
        REGISTER_LSP_NATIVE_METHODS(SigBypass);
    }
}
