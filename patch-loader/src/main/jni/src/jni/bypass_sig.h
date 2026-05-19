#pragma once
#include <jni.h>

namespace lspd {
    void RegisterBypass(JNIEnv* env);
    void InitMapsHide(); 
    void InitFdFilesBypass(); 
}
