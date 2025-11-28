use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint};
use jni::sys::{JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use std::path::PathBuf;

#[no_mangle]
pub extern "system" fn JNI_OnLoad(_vm: jni::JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Error)
            .with_tag("TpkSig"),
    );
    jni::sys::JNI_VERSION_1_6
}

#[no_mangle]
pub extern "system" fn Java_com_quicktvui_TpkSig_verify(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jboolean {
    // 1. JString -> Rust String
    let path_rust: String = match env.get_string(&path) {
        Ok(jstr) => jstr.into(),
        Err(_) => {
            log::error!("Failed to convert JString to Rust String");
            return JNI_FALSE;
        }
    };

    // 2. String -> PathBuf
    let path_buf = PathBuf::from(path_rust);

    // 3. verify
    let tpk = match tpksig::Tpk::new(path_buf) {
        Ok(tpk) => tpk,
        Err(e) => {
            log::error!("Tpk::new failed: {}", e);
            return JNI_FALSE;
        }
    };

    match tpk.verify() {
        Ok(_) => JNI_TRUE,
        Err(e) => {
            log::error!("tpk.verify() failed: {}", e);
            JNI_FALSE
        }
    }
}
