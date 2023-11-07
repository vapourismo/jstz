use std::ops::Deref;

use boa_engine::{
    js_string, object::ObjectInitializer, Context, JsArgs, JsNativeError, JsObject,
    JsResult, JsString, JsValue, NativeFunction,
};
use jstz_core::{host_defined, kv::Transaction, runtime};
use jstz_crypto::public_key_hash::PublicKeyHash;
use jstz_proto::context::account::Account;

macro_rules! preamble {
    ($args:ident, $context:ident, $tx:ident) => {
        host_defined!($context, host_defined);
        let mut $tx = host_defined
            .get_mut::<Transaction>()
            .expect("Curent transaction undefined");
    };
}

macro_rules! set_value {
    ($args:ident, $value:ident, $id:tt) => {
        let $value = $args
            .get_or_undefined($id)
            .as_string()
            .ok_or_else(|| {
                JsNativeError::typ()
                    .with_message("Failed to convert js value into rust type `String`")
            })
            .map(JsString::to_std_string_escaped)?;
    };
}

macro_rules! set_integer_value {
    ($args:ident, $value:ident, $id:tt) => {
        let $value = $args
            .get_or_undefined($id)
            .as_number()
            .ok_or_else(|| {
                JsNativeError::typ()
                    .with_message("Failed to convert js value into rust type `i32`")
            })
            .and_then(|num| Ok(num as i32))?;
    };
}

fn get_public_key_hash(account: &str) -> Result<PublicKeyHash, JsNativeError> {
    PublicKeyHash::from_base58(account)
        .map_err(|_| JsNativeError::typ().with_message("Could not parse the address."))
}

pub struct AccountApi;

impl AccountApi {
    fn balance(
        _this: &JsValue,
        args: &[JsValue],
        context: &mut Context,
    ) -> JsResult<JsValue> {
        preamble!(args, context, tx);
        set_value!(args, account, 0);

        let pkh = get_public_key_hash(account.as_str())?;

        let result =
            runtime::with_global_host(|rt| Account::balance(rt.deref(), &mut tx, &pkh))?;
        if result <= i32::MAX as u64 {
            Ok(JsValue::from(result as i32))
        } else {
            Err(JsNativeError::typ().with_message("Balance overflow").into())
        }
    }

    fn set_balance(
        _this: &JsValue,
        args: &[JsValue],
        context: &mut Context,
    ) -> JsResult<JsValue> {
        preamble!(args, context, tx);
        set_value!(args, account, 0);
        set_integer_value!(args, balance, 1);

        let pkh = get_public_key_hash(account.as_str())?;

        let current_balance =
            runtime::with_global_host(|rt| Account::balance(rt.deref(), &mut tx, &pkh))?;
        let balance_delta = (balance as u64) - current_balance;

        runtime::with_global_host(|rt| {
            Account::deposit(rt.deref(), &mut tx, &pkh, balance_delta)
        })?;

        Ok(JsValue::undefined())
    }

    fn code(
        _this: &JsValue,
        args: &[JsValue],
        context: &mut Context,
    ) -> JsResult<JsValue> {
        preamble!(args, context, tx);
        set_value!(args, account, 0);

        let pkh = get_public_key_hash(account.as_str())?;

        let result = runtime::with_global_host(|rt| {
            Account::contract_code(rt.deref(), &mut tx, &pkh)
        })?;

        match result {
            Some(value) => Ok(JsValue::String(value.to_string().into())),
            None => Ok(JsValue::null()),
        }
    }

    fn set_code(
        _this: &JsValue,
        args: &[JsValue],
        context: &mut Context,
    ) -> JsResult<JsValue> {
        preamble!(args, context, tx);
        set_value!(args, account, 0);
        set_value!(args, code, 1);

        let pkh = get_public_key_hash(account.as_str())?;

        runtime::with_global_host(|rt| {
            Account::set_contract_code(rt.deref(), &mut tx, &pkh, code)
        })?;

        Ok(JsValue::undefined())
    }

    pub fn init(self, context: &mut boa_engine::Context<'_>) -> JsObject {
        let storage = ObjectInitializer::new(context)
            .function(
                NativeFunction::from_fn_ptr(Self::balance),
                js_string!("balance"),
                1,
            )
            .function(
                NativeFunction::from_fn_ptr(Self::set_balance),
                js_string!("set_balance"),
                2,
            )
            .function(
                NativeFunction::from_fn_ptr(Self::code),
                js_string!("code"),
                1,
            )
            .function(
                NativeFunction::from_fn_ptr(Self::set_code),
                js_string!("set_code"),
                2,
            )
            .build();

        storage
    }
}
