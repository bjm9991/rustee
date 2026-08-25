/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* implements GPD_SPE_007 v1.0 + GPD_EPR_028. Identifiers from the GP table.
 * Independently written. Not copied from OP-TEE or from GP PDF prose. */
#ifndef TEE_CLIENT_API_H
#define TEE_CLIENT_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TEEC_CONFIG_PAYLOAD_REF_COUNT 4
#define TEEC_CONFIG_SHAREDMEM_MAX_SIZE 0x80000u

typedef uint32_t TEEC_Result;

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEEC_UUID;

typedef struct {
	uintptr_t imp;
} TEEC_Context;

typedef struct {
	uintptr_t imp;
} TEEC_Session;

#define TEEC_MEM_INPUT  0x00000001u
#define TEEC_MEM_OUTPUT 0x00000002u

typedef struct {
	void *buffer;
	size_t size;
	uint32_t flags;
	uint32_t reserved;
} TEEC_SharedMemory;

typedef struct {
	void *buffer;
	size_t size;
} TEEC_TempMemoryReference;

typedef struct {
	TEEC_SharedMemory *parent;
	size_t size;
	size_t offset;
} TEEC_RegisteredMemoryReference;

typedef struct {
	uint32_t a;
	uint32_t b;
} TEEC_Value;

typedef union {
	TEEC_TempMemoryReference tmpref;
	TEEC_RegisteredMemoryReference memref;
	TEEC_Value value;
} TEEC_Parameter;

#define TEEC_NONE                   0x00000000u
#define TEEC_VALUE_INPUT            0x00000001u
#define TEEC_VALUE_OUTPUT           0x00000002u
#define TEEC_VALUE_INOUT            0x00000003u
#define TEEC_MEMREF_TEMP_INPUT      0x00000005u
#define TEEC_MEMREF_TEMP_OUTPUT     0x00000006u
#define TEEC_MEMREF_TEMP_INOUT      0x00000007u
#define TEEC_MEMREF_WHOLE           0x0000000Cu
#define TEEC_MEMREF_PARTIAL_INPUT   0x0000000Du
#define TEEC_MEMREF_PARTIAL_OUTPUT  0x0000000Eu
#define TEEC_MEMREF_PARTIAL_INOUT   0x0000000Fu

#define TEEC_PARAM_TYPES(t0, t1, t2, t3) \
	((uint32_t)(t0) | ((uint32_t)(t1) << 4) | ((uint32_t)(t2) << 8) | ((uint32_t)(t3) << 12))
#define TEEC_PARAM_TYPE_GET(t, i) (((t) >> ((i) * 4)) & 0xFu)

typedef struct {
	uint32_t started;
	uint32_t paramTypes;
	TEEC_Parameter params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	uintptr_t imp;
} TEEC_Operation;

#define TEEC_LOGIN_PUBLIC             0x00000000u
#define TEEC_LOGIN_USER               0x00000001u
#define TEEC_LOGIN_GROUP              0x00000002u
#define TEEC_LOGIN_APPLICATION        0x00000004u
#define TEEC_LOGIN_USER_APPLICATION   0x00000005u
#define TEEC_LOGIN_GROUP_APPLICATION  0x00000006u

#define TEEC_SUCCESS                0x00000000u
#define TEEC_ERROR_GENERIC          0xFFFF0000u
#define TEEC_ERROR_ACCESS_DENIED    0xFFFF0001u
#define TEEC_ERROR_CANCEL           0xFFFF0002u
#define TEEC_ERROR_ACCESS_CONFLICT  0xFFFF0003u
#define TEEC_ERROR_EXCESS_DATA      0xFFFF0004u
#define TEEC_ERROR_BAD_FORMAT       0xFFFF0005u
#define TEEC_ERROR_BAD_PARAMETERS   0xFFFF0006u
#define TEEC_ERROR_BAD_STATE        0xFFFF0007u
#define TEEC_ERROR_ITEM_NOT_FOUND   0xFFFF0008u
#define TEEC_ERROR_NOT_IMPLEMENTED  0xFFFF0009u
#define TEEC_ERROR_NOT_SUPPORTED    0xFFFF000Au
#define TEEC_ERROR_NO_DATA          0xFFFF000Bu
#define TEEC_ERROR_OUT_OF_MEMORY    0xFFFF000Cu
#define TEEC_ERROR_BUSY             0xFFFF000Du
#define TEEC_ERROR_COMMUNICATION    0xFFFF000Eu
#define TEEC_ERROR_SECURITY         0xFFFF000Fu
#define TEEC_ERROR_SHORT_BUFFER     0xFFFF0010u
#define TEEC_ERROR_TARGET_DEAD      0xFFFF3024u

#define TEEC_ORIGIN_API          0x00000001u
#define TEEC_ORIGIN_COMMS        0x00000002u
#define TEEC_ORIGIN_TEE          0x00000003u
#define TEEC_ORIGIN_TRUSTED_APP  0x00000004u

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context);
void TEEC_FinalizeContext(TEEC_Context *context);
TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session,
	const TEEC_UUID *destination, uint32_t connectionMethod,
	const void *connectionData, TEEC_Operation *operation,
	uint32_t *returnOrigin);
void TEEC_CloseSession(TEEC_Session *session);
TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID,
	TEEC_Operation *operation, uint32_t *returnOrigin);
TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context,
	TEEC_SharedMemory *sharedMem);
TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context,
	TEEC_SharedMemory *sharedMem);
void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMem);
void TEEC_RequestCancellation(TEEC_Operation *operation);

#ifdef __cplusplus
}
#endif
#endif /* TEE_CLIENT_API_H */
