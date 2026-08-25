/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Independently written types. Implements GPD_SPE_010 v1.3.1. */

#ifndef TEE_API_TYPES_H
#define TEE_API_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <tee_api_defines.h>

typedef uint32_t TEE_Result;

typedef struct {
	uint32_t timeLow;
	uint16_t timeMid;
	uint16_t timeHiAndVersion;
	uint8_t clockSeqAndNode[8];
} TEE_UUID;

typedef struct {
	uint32_t login;
	TEE_UUID uuid;
} TEE_Identity;

typedef union {
	struct {
		void *buffer;
		size_t size;
	} memref;
	struct {
		uint32_t a;
		uint32_t b;
	} value;
} TEE_Param;

typedef struct {
	uint32_t seconds;
	uint32_t millis;
} TEE_Time;

typedef struct __TEE_TASessionHandle *TEE_TASessionHandle;
typedef struct __TEE_PropSetHandle *TEE_PropSetHandle;
typedef struct __TEE_ObjectHandle *TEE_ObjectHandle;
typedef struct __TEE_ObjectEnumHandle *TEE_ObjectEnumHandle;
typedef struct __TEE_OperationHandle *TEE_OperationHandle;

typedef uint32_t TEE_ObjectType;
typedef uint32_t TEE_Whence;
typedef uint32_t TEE_OperationMode;
typedef uint32_t TEE_BigInt;
typedef uint32_t TEE_BigIntFMM;
typedef uint32_t TEE_BigIntFMMContext;

typedef struct {
	uint32_t objectType;
	uint32_t objectSize;
	uint32_t maxObjectSize;
	uint32_t objectUsage;
	size_t dataSize;
	size_t dataPosition;
	uint32_t handleFlags;
} TEE_ObjectInfo;

typedef struct {
	uint32_t attributeID;
	union {
		struct {
			void *buffer;
			size_t length;
		} ref;
		struct {
			uint32_t a, b;
		} value;
	} content;
} TEE_Attribute;

typedef struct {
	uint32_t algorithm;
	uint32_t operationClass;
	uint32_t mode;
	uint32_t digestLength;
	uint32_t maxKeySize;
	uint32_t keySize;
	uint32_t requiredKeyUsage;
	uint32_t handleState;
} TEE_OperationInfo;

#endif /* TEE_API_TYPES_H */
