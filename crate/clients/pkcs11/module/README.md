# PKCS#11 Driver

## Foreword

This code is originally forked from <https://github.com/google/native-pkcs11/> commit
cc26f7f8a70359d98b9b589a712f7a559688b348 released under Apache License 2.0, provided in this directory. Since Google did
not seem to be interested in our PRs, the original code has been copied and heavily modified to cover our uses cases.

Original authors include:

- "Brandon Weeks <bweeks@google.com>"
- "Kevin King <kcking@google.com>"

The modified code is released under the Business Source License 1.1, as is the rest of this project.

## Implementing

The `native_pkcs11_traits::Backend` trait must be implemented to add support for
a store. Backends are registered in the exported
`C_GetFunctionList` function. In order to register a backend, export the method from
the crate. For example:

```rust
use native_pkcs11::{CKR_OK, CK_FUNCTION_LIST_PTR_PTR, CK_RV, FUNC_LIST};

#[no_mangle]
pub extern "C" fn C_GetFunctionList(function_list_ptr_ptr: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    // add the custom backend
    native_pkcs11_traits::register_backend(Box::new(backend::MyBackend {}));
    // assign this function to the native-pkcs11 function list C_GetFunctionList
    FUNC_LIST.C_GetFunctionList = Some(C_GetFunctionList);
    // assign the result to the output parameter
    unsafe { *function_list_ptr_ptr = &mut FUNC_LIST };
    return CKR_OK;
}
```
