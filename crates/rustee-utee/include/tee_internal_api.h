/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Independently written prototypes. Implements GPD_SPE_010 v1.3.1. */

#ifndef TEE_INTERNAL_API_H
#define TEE_INTERNAL_API_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

#ifdef __cplusplus
extern "C" {
#endif

TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator,
	const char *name, char *valueBuffer, size_t *valueBufferLen);
TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator,
	const char *name, bool *value);
TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator,
	const char *name, uint32_t *value);
TEE_Result TEE_GetPropertyAsU64(TEE_PropSetHandle propsetOrEnumerator,
	const char *name, uint64_t *value);
TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator,
	const char *name, void *valueBuffer, size_t *valueBufferLen);
TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator,
	const char *name, TEE_UUID *value);
TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator,
	const char *name, TEE_Identity *value);
TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator);
void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator);
void TEE_StartPropertyEnumerator(TEE_PropSetHandle enumerator,
	TEE_PropSetHandle propSet);
void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator);
TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator,
	void *nameBuffer, size_t *nameBufferLen);
TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator);

void TEE_Panic(TEE_Result panicCode);

TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
	uint32_t cancellationRequestTimeout, uint32_t paramTypes,
	TEE_Param params[TEE_NUM_PARAMS], TEE_TASessionHandle *session,
	uint32_t *returnOrigin);
void TEE_CloseTASession(TEE_TASessionHandle session);
TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
	uint32_t cancellationRequestTimeout, uint32_t commandID,
	uint32_t paramTypes, TEE_Param params[TEE_NUM_PARAMS],
	uint32_t *returnOrigin);

bool TEE_GetCancellationFlag(void);
bool TEE_UnmaskCancellation(void);
bool TEE_MaskCancellation(void);

TEE_Result TEE_CheckMemoryAccessRights(uint32_t accessFlags, void *buffer,
	size_t size);
void TEE_SetInstanceData(void *instanceData);
void *TEE_GetInstanceData(void);
void *TEE_Malloc(size_t size, uint32_t hint);
void *TEE_Realloc(void *buffer, size_t newSize);
void TEE_Free(void *buffer);
void TEE_MemMove(void *dest, const void *src, size_t size);
int32_t TEE_MemCompare(const void *buffer1, const void *buffer2, size_t size);
void TEE_MemFill(void *buff, uint32_t x, size_t size);

void TEE_GetSystemTime(TEE_Time *time);
TEE_Result TEE_Wait(uint32_t timeout);
TEE_Result TEE_GetTAPersistentTime(TEE_Time *time);
TEE_Result TEE_SetTAPersistentTime(const TEE_Time *time);
void TEE_GetREETime(TEE_Time *time);

TEE_Result TEE_IsAlgorithmSupported(uint32_t algId, uint32_t element);
void TEE_GenerateRandom(void *randomBuffer, size_t randomBufferLen);

size_t TEE_BigIntFMMSizeInU32(size_t modulusSizeInBits);
size_t TEE_BigIntFMMContextSizeInU32(size_t modulusSizeInBits);
void TEE_BigIntInit(TEE_BigInt *bigInt, size_t len);
TEE_Result TEE_BigIntInitFMMContext1(TEE_BigIntFMMContext *context, size_t len,
	const TEE_BigInt *modulus);
void TEE_BigIntInitFMMContext(TEE_BigIntFMMContext *context, size_t len,
	const TEE_BigInt *modulus);
void TEE_BigIntInitFMM(TEE_BigIntFMM *bigIntFMM, size_t len);

TEE_Result TA_CreateEntryPoint(void);
void TA_DestroyEntryPoint(void);
TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
	TEE_Param params[TEE_NUM_PARAMS], void **sessionContext);
void TA_CloseSessionEntryPoint(void *sessionContext);
TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
	uint32_t paramTypes, TEE_Param params[TEE_NUM_PARAMS]);

#ifdef __cplusplus
}
#endif

#endif /* TEE_INTERNAL_API_H */
