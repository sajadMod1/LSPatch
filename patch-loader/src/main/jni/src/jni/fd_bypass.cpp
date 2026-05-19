#include "bypass_sig.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

namespace lsplant {

    // مصفوفة بسيطة لتخزين الـ FDs التي تم إعادة توجيهها (لتحسين الأداء)
    // في المشاريع الكبيرة يُفضل استخدام std::unordered_map
    
    CREATE_HOOK_STUB_ENTRY("openat", int, hook_openat, (int dirfd, const char* pathname, int flags, mode_t mode), {
        // إذا كان المسار هو الملف المعدل، نقوم بفتحه بأسلوب لا يكشف التعديل
        if (pathname != nullptr && strstr(pathname, "libgame.so")) { 
            // نعيد مسار الملف الأصلي (يجب أن تضعه في مسار آمن)
            return backup(dirfd, "/data/app/~~.../lib/arm64/libgame_original.so", flags, mode);
        }
        return backup(dirfd, pathname, flags, mode);
    });

    CREATE_HOOK_STUB_ENTRY("fstat", int, hook_fstat, (int fd, void* buf), {
        int res = backup(fd, buf);
        
        // إذا نجح الـ fstat، نتأكد أننا لا نسرب معلومات الـ Inode الخاصة بالملف المعدل
        if (res == 0 && buf != nullptr) {
            char path[PATH_MAX];
            char fd_path[64];
            snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
            
            if (readlink(fd_path, path, sizeof(path)) != -1) {
                if (strstr(path, "libgame.so")) {
                    // هنا نقوم بـ "تمويه" الـ Stat ليطابق ملفاً عادياً 
                    // أو نجبره على إرجاع بيانات ثابتة لا تشكك الحماية
                    struct stat* st = static_cast<struct stat*>(buf);
                    st->st_dev = 1; 
                    st->st_ino = 12345; // رقم Inode وهمي
                }
            }
        }
        return res;
    });

    void RegisterFDHooks(const HookHandler &handler) {
        void* sym_openat = Dlsym(handler, "openat");
        void* sym_fstat = Dlsym(handler, "fstat");
        
        if (sym_openat) HookSymNoHandle(handler, sym_openat, hook_openat);
        if (sym_fstat) HookSymNoHandle(handler, sym_fstat, hook_fstat);
    }
}
