use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;
use std::path::PathBuf;

#[no_mangle]
pub extern "system" fn JNI_OnLoad(_vm: jni::JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    jni::sys::JNI_VERSION_1_6
}

#[no_mangle]
pub extern "system" fn Java_com_quicktvui_TpkSig_verify(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jint {
    // 1. JString -> Rust String
    let path_rust: String = match env.get_string(&path) {
        Ok(jstr) => jstr.into(),
        Err(_) => {
            return 1;
        }
    };

    // 2. String -> PathBuf
    let path_buf = PathBuf::from(path_rust);

    // 3. verify
    let tpk = match tpksig::Tpk::new(path_buf) {
        Ok(tpk) => tpk,
        Err(e) => {
            return 1;
        }
    };

    match tpk.verify() {
        Ok(_) => 0,
        Err(e) => {
            return 1;
        }
    }
}
