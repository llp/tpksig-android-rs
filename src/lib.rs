use jni::objects::{JClass, JString};
use jni::sys::jboolean;
use jni::sys::{JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use std::path::PathBuf;

#[no_mangle]
pub extern "system" fn Java_com_quicktvui_TpkSig_verify(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jboolean {
    // 1. JString -> Rust String
    let path_rust: String = match env.get_string(&path) {
        Ok(jstr) => jstr.into(),
        Err(_) => return JNI_FALSE,
    };

    // 2. String -> PathBuf
    let path_buf = PathBuf::from(path_rust);

    // 3. verify
    let tpk = match tpksig::Tpk::new(path_buf) {
        Ok(tpk) => tpk,
        Err(e) => {
            eprintln!("verify error: {}", e);
            return JNI_FALSE;
        }
    };

    match tpk.verify() {
        Ok(_) => JNI_TRUE,
        Err(e) => {
            eprintln!("verify error: {}", e);
            JNI_FALSE
        }
    }
}

// cargo ndk -t arm64-v8a -o ../android_app/app/src/main/jniLibs build --release
// cargo ndk -t armeabi-v7a -o ../android_app/app/src/main/jniLibs build --release
// cargo ndk -t x86_64 -o ../android_app/app/src/main/jniLibs build --release
// cargo ndk -t x86 -o ../android_app/app/src/main/jniLibs build --release

//cargo ndk -t arm64-v8a -o ./output build --release

