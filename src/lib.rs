use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jint, jobject};
use jni::JNIEnv;
use std::path::PathBuf;

use tpksig::error::TpkSigError;
use tpksig::scheme_v2::{SignatureSchemeV2, Signers as V2Signers};
use tpksig::scheme_v3::{SignatureSchemeV3, Signers as V3Signers};
use tpksig::{RawData, SigningBlock, ValueSigningBlock};

#[no_mangle]
pub extern "system" fn JNI_OnLoad(_vm: jni::JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    jni::sys::JNI_VERSION_1_6
}

#[no_mangle]
pub extern "system" fn Java_com_quicktvui_sign_TpkSig_verify(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jint {
    let path_rust: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(_) => return 1,
    };
    let tpk = match tpksig::Tpk::new(PathBuf::from(path_rust)) {
        Ok(t) => t,
        Err(_) => return 1,
    };
    // 3. 调用 verify 并映射错误类型
    match tpk.verify() {
        Ok(_) => 0,
        Err(TpkSigError::Io(_)) => 2,
        Err(TpkSigError::ApkIsRaw) => 3,
        Err(TpkSigError::NoSigner) => 4,
        Err(TpkSigError::NoSignature) => 5,
        Err(TpkSigError::NoDigest) => 6,
        Err(TpkSigError::InvalidSignedData) => 7,
        Err(TpkSigError::V3NotSupported) => 8,
        Err(TpkSigError::VerificationFailed(_)) => 9,
        Err(TpkSigError::PubKeyError(_)) => 10,
        Err(TpkSigError::UnsupportedAlgorithm(_)) => 11,
        Err(TpkSigError::DigestMismatch) => 12,
        Err(TpkSigError::InvalidApkStructure(_)) => 13,
        Err(TpkSigError::InvalidStartSignature) => 14,
        Err(TpkSigError::InvalidEndSignature) => 15,
        Err(TpkSigError::EocdNotFound) => 16,
        Err(TpkSigError::InvalidEocd) => 17,
        Err(TpkSigError::Format(_)) => 18,
        Err(TpkSigError::Signature(_)) => 19,
        Err(TpkSigError::Padding(_)) => 20,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_quicktvui_sign_TpkSig_getSigningBlock(
    mut env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jobject {
    let path_rust: String = match env.get_string(&path) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };

    let tpk = match tpksig::Tpk::new(PathBuf::from(path_rust)) {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };

    let sb = match tpk.get_signing_block() {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    to_java_signing_block(&mut env, &sb)
        .map(|o| o.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn to_java_signing_block<'local>(
    env: &mut JNIEnv<'local>,
    sb: &SigningBlock,
) -> Option<JObject<'local>> {
    let obj = env
        .new_object("com/quicktvui/sign/SigningBlock", "()V", &[])
        .ok()?;

    env.set_field(
        &obj,
        "fileOffsetStart",
        "J",
        JValue::Long(sb.file_offset_start as i64),
    )
    .ok()?;
    env.set_field(
        &obj,
        "fileOffsetEnd",
        "J",
        JValue::Long(sb.file_offset_end as i64),
    )
    .ok()?;
    env.set_field(
        &obj,
        "sizeOfBlockStart",
        "J",
        JValue::Long(sb.size_of_block_start as i64),
    )
    .ok()?;
    env.set_field(
        &obj,
        "contentSize",
        "J",
        JValue::Long(sb.content_size as i64),
    )
    .ok()?;
    env.set_field(
        &obj,
        "sizeOfBlockEnd",
        "J",
        JValue::Long(sb.size_of_block_end as i64),
    )
    .ok()?;

    let magic = env.byte_array_from_slice(&sb.magic).ok()?;
    env.set_field(&obj, "magic", "[B", JValue::from(&magic))
        .ok()?;

    let list = env
        .new_object("java/util/ArrayList", "(I)V", &[10i32.into()])
        .ok()?;

    for block in &sb.content {
        let java_block = match block {
            ValueSigningBlock::SignatureSchemeV2Block(v2) => create_v2_block(env, v2)?,
            ValueSigningBlock::SignatureSchemeV3Block(v3) => create_v3_block(env, v3)?,
            ValueSigningBlock::BaseSigningBlock(raw) => create_base_block(env, raw)?,
        };
        env.call_method(
            &list,
            "add",
            "(Ljava/lang/Object;)Z",
            &[JValue::Object(&java_block)],
        )
        .ok()?;
    }

    env.set_field(&obj, "content", "Ljava/util/List;", (&list).into())
        .ok()?;
    Some(obj)
}

fn create_v2_block<'a>(env: &mut JNIEnv<'a>, v2: &SignatureSchemeV2) -> Option<JObject<'a>> {
    let signers_obj = create_java_signers_v2(env, &v2.signers)?;

    let v2_obj = env
        .new_object("com/quicktvui/sign/SignatureSchemeV2", "()V", &[])
        .ok()?;
    env.set_field(&v2_obj, "size", "J", JValue::Long(v2.size as i64))
        .ok()?;
    env.set_field(&v2_obj, "id", "I", JValue::Int(v2.id as i32))
        .ok()?;
    env.set_field(
        &v2_obj,
        "signers",
        "Lcom/quicktvui/sign/Signers;",
        (&signers_obj).into(),
    )
    .ok()?;

    let wrapper = env
        .new_object(
            "com/quicktvui/sign/ValueSigningBlock$SignatureSchemeV2Block",
            "()V",
            &[],
        )
        .ok()?;
    env.set_field(
        &wrapper,
        "signatureSchemeV2",
        "Lcom/quicktvui/sign/SignatureSchemeV2;",
        (&v2_obj).into(),
    )
    .ok()?;
    Some(wrapper)
}

fn create_v3_block<'a>(env: &mut JNIEnv<'a>, v3: &SignatureSchemeV3) -> Option<JObject<'a>> {
    let signers_obj = create_java_signers_v3(env, &v3.signers)?;

    let v3_obj = env
        .new_object("com/quicktvui/sign/SignatureSchemeV3", "()V", &[])
        .ok()?;
    env.set_field(&v3_obj, "size", "J", JValue::Long(v3.size as i64))
        .ok()?;
    env.set_field(&v3_obj, "id", "I", JValue::Int(v3.id as i32))
        .ok()?;
    env.set_field(
        &v3_obj,
        "signers",
        "Lcom/quicktvui/sign/Signers;",
        (&signers_obj).into(),
    )
    .ok()?;

    let wrapper = env
        .new_object(
            "com/quicktvui/sign/ValueSigningBlock$SignatureSchemeV3Block",
            "()V",
            &[],
        )
        .ok()?;
    env.set_field(
        &wrapper,
        "signatureSchemeV3",
        "Lcom/quicktvui/sign/SignatureSchemeV3;",
        (&v3_obj).into(),
    )
    .ok()?;
    Some(wrapper)
}

fn create_base_block<'a>(env: &mut JNIEnv<'a>, raw: &RawData) -> Option<JObject<'a>> {
    let raw_obj = env
        .new_object("com/quicktvui/sign/RawData", "()V", &[])
        .ok()?;
    env.set_field(&raw_obj, "size", "J", JValue::Long(raw.size as i64))
        .ok()?;
    env.set_field(&raw_obj, "id", "I", JValue::Int(raw.id as i32))
        .ok()?;

    let data_arr = env.byte_array_from_slice(&raw.data).ok()?;
    env.set_field(&raw_obj, "data", "[B", JValue::from(&data_arr))
        .ok()?;

    let wrapper = env
        .new_object(
            "com/quicktvui/sign/ValueSigningBlock$BaseSigningBlock",
            "()V",
            &[],
        )
        .ok()?;
    env.set_field(
        &wrapper,
        "rawData",
        "Lcom/quicktvui/sign/RawData;",
        (&raw_obj).into(),
    )
    .ok()?;
    Some(wrapper)
}

fn create_java_signers_v2<'a>(env: &mut JNIEnv<'a>, signers: &V2Signers) -> Option<JObject<'a>> {
    let signers_obj = env
        .new_object("com/quicktvui/sign/Signers", "()V", &[])
        .ok()?;
    env.set_field(&signers_obj, "size", "J", JValue::Long(signers.size as i64))
        .ok()?;

    let list = env
        .new_object(
            "java/util/ArrayList",
            "(I)V",
            &[JValue::Int(signers.signers_data.len() as i32)],
        )
        .ok()?;

    for signer in &signers.signers_data {
        let signer_obj = env
            .new_object("com/quicktvui/sign/Signer", "()V", &[])
            .ok()?;
        env.set_field(&signer_obj, "size", "J", JValue::Long(signer.size as i64))
            .ok()?;

        // null
        let null_obj = JObject::null();
        env.set_field(
            &signer_obj,
            "signedData",
            "Lcom/quicktvui/sign/SignedData;",
            JValue::Object(&null_obj),
        )
        .ok()?;
        env.set_field(
            &signer_obj,
            "signatures",
            "Lcom/quicktvui/sign/Signatures;",
            JValue::Object(&null_obj),
        )
        .ok()?;

        // 公钥
        let pk_obj = env
            .new_object("com/quicktvui/sign/PubKey", "()V", &[])
            .ok()?;
        env.set_field(
            &pk_obj,
            "size",
            "J",
            JValue::Long(signer.pub_key.size as i64),
        )
        .ok()?;
        let key_arr = env.byte_array_from_slice(&signer.pub_key.data).ok()?;
        env.set_field(&pk_obj, "data", "[B", JValue::from(&key_arr))
            .ok()?;
        env.set_field(
            &signer_obj,
            "pubKey",
            "Lcom/quicktvui/sign/PubKey;",
            (&pk_obj).into(),
        )
        .ok()?;

        env.call_method(
            &list,
            "add",
            "(Ljava/lang/Object;)Z",
            &[JValue::Object(&signer_obj)],
        )
        .ok()?;
    }

    env.set_field(
        &signers_obj,
        "signersData",
        "Ljava/util/List;",
        (&list).into(),
    )
    .ok()?;
    Some(signers_obj)
}

fn create_java_signers_v3<'a>(env: &mut JNIEnv<'a>, signers: &V3Signers) -> Option<JObject<'a>> {
    let signers_obj = env
        .new_object("com/quicktvui/sign/Signers", "()V", &[])
        .ok()?;
    env.set_field(&signers_obj, "size", "J", JValue::Long(signers.size as i64))
        .ok()?;

    let list = env
        .new_object(
            "java/util/ArrayList",
            "(I)V",
            &[JValue::Int(signers.signers_data.len() as i32)],
        )
        .ok()?;

    for signer in &signers.signers_data {
        let signer_obj = env
            .new_object("com/quicktvui/sign/Signer", "()V", &[])
            .ok()?;
        env.set_field(&signer_obj, "size", "J", JValue::Long(signer.size as i64))
            .ok()?;

        let null_obj = JObject::null();
        env.set_field(
            &signer_obj,
            "signedData",
            "Lcom/quicktvui/sign/SignedData;",
            JValue::Object(&null_obj),
        )
        .ok()?;
        env.set_field(
            &signer_obj,
            "signatures",
            "Lcom/quicktvui/sign/Signatures;",
            JValue::Object(&null_obj),
        )
        .ok()?;

        let pk_obj = env
            .new_object("com/quicktvui/sign/PubKey", "()V", &[])
            .ok()?;
        env.set_field(
            &pk_obj,
            "size",
            "J",
            JValue::Long(signer.pub_key.size as i64),
        )
        .ok()?;
        let key_arr = env.byte_array_from_slice(&signer.pub_key.data).ok()?;
        env.set_field(&pk_obj, "data", "[B", JValue::from(&key_arr))
            .ok()?;
        env.set_field(
            &signer_obj,
            "pubKey",
            "Lcom/quicktvui/sign/PubKey;",
            (&pk_obj).into(),
        )
        .ok()?;

        env.call_method(
            &list,
            "add",
            "(Ljava/lang/Object;)Z",
            &[JValue::Object(&signer_obj)],
        )
        .ok()?;
    }

    env.set_field(
        &signers_obj,
        "signersData",
        "Ljava/util/List;",
        (&list).into(),
    )
    .ok()?;
    Some(signers_obj)
}
