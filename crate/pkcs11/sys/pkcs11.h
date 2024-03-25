// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This header file incorporates WIN32-specific advice from
// https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/cs01/include/pkcs11-v3.1/pkcs11.h.

#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllexport) name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport)(*name)
/* There is a matching pop below.  */
#pragma pack(push, cryptoki, 1)
#else
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#endif

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#endif

#include "third_party/pkcs11/pkcs11.h"

#if defined(_WIN32) || defined(CRYPTOKI_FORCE_WIN32)
#pragma pack(pop, cryptoki)
#endif