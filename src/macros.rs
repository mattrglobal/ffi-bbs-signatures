macro_rules! add_message_impl {
    (
     $name_string:ident,
     $name_bytes:ident,
     $name_prehash:ident,
     $static:expr
    ) => {
        #[no_mangle]
        pub extern "C" fn $name_string(
            handle: u64,
            message: FfiStr<'_>,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.into_string();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                ctx.messages
                    .push(SignatureMessage::hash(message.as_bytes()));
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $name_bytes(
            handle: u64,
            message: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.to_vec();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                ctx.messages.push(SignatureMessage::hash(&message));
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $name_prehash(
            handle: u64,
            message: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.to_vec();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            $static.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
                let msg = SignatureMessage::try_from(message)?;
                ctx.messages.push(msg);
                Ok(())
            });
            err.get_code().code()
        }
    };
    (
     $name_string:ident,
     $name_bytes:ident,
     $name_prehash:ident,
     $static:expr,
     $index:ident
    ) => {
        #[no_mangle]
        pub extern "C" fn $name_string(
            handle: u64,
            index: $index,
            message: FfiStr<'_>,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.into_string();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                ctx.messages
                    .insert(index as usize, SignatureMessage::hash(message.as_bytes()));
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $name_bytes(
            handle: u64,
            index: $index,
            message: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.to_vec();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                ctx.messages
                    .insert(index as usize, SignatureMessage::hash(&message));
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $name_prehash(
            handle: u64,
            index: $index,
            message: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.to_vec();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            $static.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
                let msg = SignatureMessage::try_from(message)?;
                ctx.messages.insert(index as usize, msg);
                Ok(())
            });
            err.get_code().code()
        }
    };
}

macro_rules! add_bytes_impl {
    ($name:ident,$static:expr,$property:ident,$type:ident) => {
        #[no_mangle]
        pub extern "C" fn $name(handle: u64, value: ByteArray, err: &mut ExternError) -> i32 {
            let value = value.to_vec();
            if value.is_empty() {
                *err = ExternError::new_error(
                    ErrorCode::new(1),
                    &format!("{} cannot be empty", stringify!($type)),
                );
                return 1;
            }
            $static.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
                let v = $type::try_from(value)?;
                ctx.$property = Some(v);
                Ok(())
            });
            err.get_code().code()
        }
    };
    (
     $name_string:ident,
     $name_bytes:ident,
     $name_prehash:ident,
     $static:expr,
     $property:ident,
     $type:ident) => {
        #[no_mangle]
        pub extern "C" fn $name_string(
            handle: u64,
            message: FfiStr<'_>,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.into_string();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                ctx.$property = Some($type::hash(message.as_bytes()));
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $name_bytes(handle: u64, value: ByteArray, err: &mut ExternError) -> i32 {
            let value = value.to_vec();
            if value.is_empty() {
                *err = ExternError::new_error(
                    ErrorCode::new(1),
                    &format!("{} cannot be empty", stringify!($type)),
                );
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                ctx.$property = Some($type::hash(value));
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $name_prehash(
            handle: u64,
            value: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let value = value.to_vec();
            if value.is_empty() {
                *err = ExternError::new_error(
                    ErrorCode::new(1),
                    &format!("{} cannot be empty", stringify!($type)),
                );
                return 1;
            }
            $static.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
                let v = $type::try_from(value)?;
                ctx.$property = Some(v);
                Ok(())
            });
            err.get_code().code()
        }
    };
}

macro_rules! add_proof_message_impl {
    (
     $name_string:ident,
     $name_bytes:ident,
     $name_prehash:ident,
     $static:expr
    ) => {
        #[no_mangle]
        pub extern "C" fn $name_string(
            handle: u64,
            message: FfiStr<'_>,
            xtype: ProofMessageType,
            blinding_factor: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.into_string();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            let bf = blinding_factor.to_vec();
            if bf.is_empty() && xtype == ProofMessageType::HiddenExternalBlinding {
                *err = ExternError::new_error(ErrorCode::new(1), "Blinding Factor cannot be empty");
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                let m = match xtype {
                    ProofMessageType::Revealed => {
                        ProofMessage::Revealed(SignatureMessage::hash(message.as_bytes()))
                    }
                    ProofMessageType::HiddenProofSpecificBlinding => {
                        ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(
                            SignatureMessage::hash(message.as_bytes()),
                        ))
                    }
                    ProofMessageType::HiddenExternalBlinding => {
                        ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
                            SignatureMessage::hash(message.as_bytes()),
                            ProofNonce::hash(bf.as_slice()),
                        ))
                    }
                };
                ctx.messages.push(m);
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $name_bytes(
            handle: u64,
            message: ByteArray,
            xtype: ProofMessageType,
            blinding_factor: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.to_vec();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            let bf = blinding_factor.to_vec();
            if bf.is_empty() && xtype == ProofMessageType::HiddenExternalBlinding {
                *err = ExternError::new_error(ErrorCode::new(1), "Blinding Factor cannot be empty");
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                let m = match xtype {
                    ProofMessageType::Revealed => {
                        ProofMessage::Revealed(SignatureMessage::hash(message.as_slice()))
                    }
                    ProofMessageType::HiddenProofSpecificBlinding => {
                        ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(
                            SignatureMessage::hash(message.as_slice()),
                        ))
                    }
                    ProofMessageType::HiddenExternalBlinding => {
                        ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
                            SignatureMessage::hash(message.as_slice()),
                            ProofNonce::hash(bf.as_slice()),
                        ))
                    }
                };
                ctx.messages.push(m);
            });
            err.get_code().code()
        }

        #[no_mangle]
        pub extern "C" fn $name_prehash(
            handle: u64,
            message: ByteArray,
            xtype: ProofMessageType,
            blinding_factor: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.to_vec();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            let bf = blinding_factor.to_vec();
            if bf.is_empty() && xtype == ProofMessageType::HiddenExternalBlinding {
                *err = ExternError::new_error(ErrorCode::new(1), "Blinding Factor cannot be empty");
                return 1;
            }
            $static.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
                let m = match xtype {
                    ProofMessageType::Revealed => {
                        ProofMessage::Revealed(SignatureMessage::try_from(message.as_slice())?)
                    }
                    ProofMessageType::HiddenProofSpecificBlinding => {
                        ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(
                            SignatureMessage::try_from(message.as_slice())?,
                        ))
                    }
                    ProofMessageType::HiddenExternalBlinding => {
                        ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
                            SignatureMessage::try_from(message.as_slice())?,
                            ProofNonce::hash(bf.as_slice()),
                        ))
                    }
                };
                ctx.messages.push(m);
                Ok(())
            });
            err.get_code().code()
        }
    };
}

#[cfg(any(target_os = "linux", feature = "java"))]
macro_rules! copy_to_jni {
    ($env:expr, $var:expr, $from:expr) => {
        if $env.set_byte_array_region($var, 0, $from).is_err() {
            return 0;
        }
    };
    ($env:expr, $var:expr, $from:expr, $val:expr) => {
        if $env.set_byte_array_region($var, 0, $from).is_err() {
            return $val;
        }
    };
}
