/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* C macros that emit ELF section .rustee.ta_head (GPD_SPE_010 TA properties). */

#ifndef RUSTEE_TA_H
#define RUSTEE_TA_H

#include <stdint.h>

#define RUSTEE_RTAH_MAGIC 0x48415452u /* 'RTAH' LE */
#define RUSTEE_RTAH_ABI   0
#define RUSTEE_RTAH_SIZE  40

struct rustee_ta_head {
	uint32_t magic;
	uint16_t abi;
	uint16_t size;
	uint8_t uuid[16];
	uint32_t stack_size;
	uint32_t data_size;
	uint8_t single_instance;
	uint8_t multi_session;
	uint8_t instance_keep_alive;
	uint8_t endian;
	uint32_t ta_version;
};

#define RUSTEE_TA_HEAD(uuid_, stack_, data_, si_, ms_, ka_, ver_) \
	__attribute__((section(".rustee.ta_head"), used)) \
	static const struct rustee_ta_head rustee_ta_head_instance = { \
		.magic = RUSTEE_RTAH_MAGIC, \
		.abi = RUSTEE_RTAH_ABI, \
		.size = RUSTEE_RTAH_SIZE, \
		.uuid = uuid_, \
		.stack_size = (stack_), \
		.data_size = (data_), \
		.single_instance = (si_), \
		.multi_session = (ms_), \
		.instance_keep_alive = (ka_), \
		.endian = 0, \
		.ta_version = (ver_), \
	}

#endif /* RUSTEE_TA_H */
