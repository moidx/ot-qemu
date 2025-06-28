/*
 * QEMU OpenTitan Key Manager device
 *
 * Copyright (c) lowRISC contributors.
 * Licensed under the Apache License, Version 2.0, see LICENSE for details.
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "hw/opentitan/ot_alert.h"
#include "hw/opentitan/ot_common.h"
#include "hw/opentitan/ot_flash.h"
#include "hw/opentitan/ot_keymgr.h"
#include "hw/opentitan/ot_kmac.h"
#include "hw/opentitan/ot_lc_ctrl.h"
#include "hw/opentitan/ot_otp.h"
#include "hw/qdev-properties.h"
#include "hw/registerfields.h"
#include "hw/riscv/ibex_common.h"
#include "hw/riscv/ibex_irq.h"
#include "tomcrypt.h"
#include "trace.h"

#define PARAM_NUM_ALERTS 2u
#define PARAM_NUM_SW_BINDING_REG 8u
#define PARAM_NUM_SALT_REG 8u
#define PARAM_NUM_KEY_VERSION_REG 1u
#define PARAM_NUM_OUT_REG 8u

#define KEYMGR_SALT_BYTES 32u
#define KEYMGR_SW_BINDING_BYTES 32u
#define KEYMGR_KEY_BYTES 64u
#define KEYMGR_KEY_WORDS (KEYMGR_KEY_BYTES / sizeof(uint32_t))
#define KEYMGR_GEN_DATA_BYTES 128u

#define KMAC_CUSTOM_STRING_ADVANCE "keymgr_adv"
#define KMAC_CUSTOM_STRING_GEN_ID "keymgr_gen_id"
#define KMAC_CUSTOM_STRING_GEN_SW "keymgr_gen_sw"
#define KMAC_CUSTOM_STRING_GEN_HW "keymgr_gen_hw"

static const uint8_t RND_CNST_CREATOR_IDENTITY_SEED[KEYMGR_KEY_BYTES] = {
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc,
    0xcd, 0xde, 0xef, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
    0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
};
static const uint8_t RND_CNST_OWNER_INT_IDENTITY_SEED[KEYMGR_KEY_BYTES] = {
    0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce,
    0xdf, 0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a,
    0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x01, 0x12,
};
static const uint8_t RND_CNST_OWNER_IDENTITY_SEED[KEYMGR_KEY_BYTES] = {
    0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf, 0xd0,
    0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b, 0x9c,
    0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03, 0x14,
};
static const uint8_t RND_CNST_SOFT_OUTPUT_SEED[32] = {
    0x37, 0x48, 0x59, 0x6a, 0x7b, 0x8c, 0x9d, 0xae, 0xbf, 0xc0, 0xd1, 0xe2,
    0xf3, 0x04, 0x15, 0x26, 0x37, 0x48, 0x59, 0x6a, 0x7b, 0x8c, 0x9d, 0xae,
    0xbf, 0xc0, 0xd1, 0xe2, 0xf3, 0x04, 0x15, 0x26,
};
static const uint8_t RND_CNST_HARD_OUTPUT_SEED[32] = {
    0x49, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf, 0xb0, 0xc1, 0xd2, 0xe3, 0xf4,
    0x05, 0x16, 0x27, 0x38, 0x49, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0xaf, 0xb0,
    0xc1, 0xd2, 0xe3, 0xf4, 0x05, 0x16, 0x27, 0x38,
};
static const uint8_t RND_CNST_AES_SEED[32] = {
    0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0, 0xb1, 0xc2, 0xd3, 0xe4, 0xf5, 0x06,
    0x17, 0x28, 0x39, 0x4a, 0x5b, 0x6c, 0x7d, 0x8e, 0x9f, 0xa0, 0xb1, 0xc2,
    0xd3, 0xe4, 0xf5, 0x06, 0x17, 0x28, 0x39, 0x4a,
};
static const uint8_t RND_CNST_KMAC_SEED[32] = {
    0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90, 0xa1, 0xb2, 0xc3, 0xd4,
    0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c,
};
static const uint8_t RND_CNST_OTBN_SEED[32] = {
    0x7f, 0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x08, 0x19, 0x2a,
    0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6,
    0xf7, 0x08, 0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e,
};
static const uint8_t RND_CNST_NONE_SEED[32] = { 0 };

/* clang-format off */
REG32(CFG_REGWEN, 0x0u)
    FIELD(CFG_REGWEN, EN, 0u, 1u)
REG32(START, 0x4u)
    FIELD(START, EN, 0u, 1u)
REG32(CONTROL_SHADOWED, 0x8u)
    FIELD(CONTROL_SHADOWED, OPERATION, 4u, 3u)
    FIELD(CONTROL_SHADOWED, CDI_SEL, 7u, 1u)
    FIELD(CONTROL_SHADOWED, DEST_SEL, 12u, 2u)
REG32(SIDELOAD_CLEAR, 0xcu)
    FIELD(SIDELOAD_CLEAR, VAL, 0u, 3u)
REG32(RESEED_INTERVAL_REGWEN, 0x10u)
    FIELD(RESEED_INTERVAL_REGWEN, EN, 0u, 1u)
REG32(RESEED_INTERVAL_SHADOWED, 0x14u)
    FIELD(RESEED_INTERVAL_SHADOWED, VAL, 0u, 16u)
REG32(SW_BINDING_REGWEN, 0x18u)
    FIELD(SW_BINDING_REGWEN, EN, 0u, 1u)
REG32(SEALING_SW_BINDING_0, 0x1cu)
REG32(SEALING_SW_BINDING_1, 0x20u)
REG32(SEALING_SW_BINDING_2, 0x24u)
REG32(SEALING_SW_BINDING_3, 0x28u)
REG32(SEALING_SW_BINDING_4, 0x2cu)
REG32(SEALING_SW_BINDING_5, 0x30u)
REG32(SEALING_SW_BINDING_6, 0x34u)
REG32(SEALING_SW_BINDING_7, 0x38u)
REG32(ATTEST_SW_BINDING_0, 0x3cu)
REG32(ATTEST_SW_BINDING_1, 0x40u)
REG32(ATTEST_SW_BINDING_2, 0x44u)
REG32(ATTEST_SW_BINDING_3, 0x48u)
REG32(ATTEST_SW_BINDING_4, 0x4cu)
REG32(ATTEST_SW_BINDING_5, 0x50u)
REG32(ATTEST_SW_BINDING_6, 0x54u)
REG32(ATTEST_SW_BINDING_7, 0x58u)
REG32(SALT_0, 0x5cu)
REG32(SALT_1, 0x60u)
REG32(SALT_2, 0x64u)
REG32(SALT_3, 0x68u)
REG32(SALT_4, 0x6cu)
REG32(SALT_5, 0x70u)
REG32(SALT_6, 0x74u)
REG32(SALT_7, 0x78u)
REG32(KEY_VERSION_0, 0x7cu)
REG32(MAX_CREATOR_KEY_VER_REGWEN, 0x80u)
    FIELD(MAX_CREATOR_KEY_VER_REGWEN, EN, 0u, 1u)
REG32(MAX_CREATOR_KEY_VER_SHADOWED, 0x84u)
    FIELD(MAX_CREATOR_KEY_VER_SHADOWED, VAL, 0u, 32u)
REG32(MAX_OWNER_INT_KEY_VER_REGWEN, 0x88u)
    FIELD(MAX_OWNER_INT_KEY_VER_REGWEN, EN, 0u, 1u)
REG32(MAX_OWNER_INT_KEY_VER_SHADOWED, 0x8cu)
    FIELD(MAX_OWNER_INT_KEY_VER_SHADOWED, VAL, 0u, 32u)
REG32(MAX_OWNER_KEY_VER_REGWEN, 0x90u)
    FIELD(MAX_OWNER_KEY_VER_REGWEN, EN, 0u, 1u)
REG32(MAX_OWNER_KEY_VER_SHADOWED, 0x94u)
    FIELD(MAX_OWNER_KEY_VER_SHADOWED, VAL, 0u, 32u)
REG32(SW_SHARE0_OUTPUT_0, 0x98u)
REG32(SW_SHARE0_OUTPUT_1, 0x9cu)
REG32(SW_SHARE0_OUTPUT_2, 0xa0u)
REG32(SW_SHARE0_OUTPUT_3, 0xa4u)
REG32(SW_SHARE0_OUTPUT_4, 0xa8u)
REG32(SW_SHARE0_OUTPUT_5, 0xacu)
REG32(SW_SHARE0_OUTPUT_6, 0xb0u)
REG32(SW_SHARE0_OUTPUT_7, 0xb4u)
REG32(SW_SHARE1_OUTPUT_0, 0xb8u)
REG32(SW_SHARE1_OUTPUT_1, 0xbcu)
REG32(SW_SHARE1_OUTPUT_2, 0xc0u)
REG32(SW_SHARE1_OUTPUT_3, 0xc4u)
REG32(SW_SHARE1_OUTPUT_4, 0xc8u)
REG32(SW_SHARE1_OUTPUT_5, 0xccu)
REG32(SW_SHARE1_OUTPUT_6, 0xd0u)
REG32(SW_SHARE1_OUTPUT_7, 0xd4u)
REG32(WORKING_STATE, 0xd8u)
    FIELD(WORKING_STATE, STATE, 0u, 3u)
REG32(OP_STATUS, 0xdcu)
    FIELD(OP_STATUS, STATUS, 0u, 2u)
REG32(ERR_CODE, 0xe0u)
    FIELD(ERR_CODE, INVALID_OP, 0u, 1u)
    FIELD(ERR_CODE, INVALID_KMAC_INPUT, 1u, 1u)
    FIELD(ERR_CODE, INVALID_SHADOW_UPDATE, 2u, 1u)
REG32(FAULT_STATUS, 0xe4u)
    FIELD(FAULT_STATUS, CMD, 0u, 1u)
    FIELD(FAULT_STATUS, KMAC_FSM, 1u, 1u)
    FIELD(FAULT_STATUS, KMAC_DONE, 2u, 1u)
    FIELD(FAULT_STATUS, KMAC_OP, 3u, 1u)
    FIELD(FAULT_STATUS, KMAC_OUT, 4u, 1u)
    FIELD(FAULT_STATUS, REGFILE_INTG, 5u, 1u)
    FIELD(FAULT_STATUS, SHADOW, 6u, 1u)
    FIELD(FAULT_STATUS, CTRL_FSM_INTG, 7u, 1u)
    FIELD(FAULT_STATUS, CTRL_FSM_CHK, 8u, 1u)
    FIELD(FAULT_STATUS, CTRL_FSM_CNT, 9u, 1u)
    FIELD(FAULT_STATUS, RESEED_CNT, 10u, 1u)
    FIELD(FAULT_STATUS, SIDE_CTRL_FSM, 11u, 1u)
    FIELD(FAULT_STATUS, SIDE_CTRL_SEL, 12u, 1u)
    FIELD(FAULT_STATUS, KEY_ECC, 13u, 1u)
REG32(DEBUG, 0xe8u)
    FIELD(DEBUG, INVALID_CREATOR_SEED, 0u, 1u)
    FIELD(DEBUG, INVALID_OWNER_SEED, 1u, 1u)
    FIELD(DEBUG, INVALID_DEV_ID, 2u, 1u)
    FIELD(DEBUG, INVALID_HEALTH_STATE, 3u, 1u)
    FIELD(DEBUG, INVALID_KEY_VERSION, 4u, 1u)
    FIELD(DEBUG, INVALID_KEY, 5u, 1u)
    FIELD(DEBUG, INVALID_DIGEST, 6u, 1u)

/* clang-format on */

#define R32_OFF(_r_) ((_r_) / sizeof(uint32_t))

#define R_LAST_REG (R_DEBUG)
#define REGS_COUNT (R_LAST_REG + 1u)
#define REGS_SIZE  (REGS_COUNT * sizeof(uint32_t))

typedef enum {
    KM_STATE_RESET,
    KM_STATE_INIT,
    KM_STATE_CREATOR_ROOT_KEY,
    KM_STATE_OWNER_INTERMEDIATE_KEY,
    KM_STATE_OWNER_KEY,
    KM_STATE_DISABLED,
    KM_STATE_WIPE,
    KM_STATE_INVALID,
} OtKeymgrFsmState;

typedef enum {
    KM_OP_ADVANCE,
    KM_OP_GENERATE_ID,
    KM_OP_GENERATE_SW_OUTPUT,
    KM_OP_GENERATE_HW_OUTPUT,
    KM_OP_DISABLE,
    KM_OP_NONE,
} OtKeymgrOperation;

static void ot_keymgr_process_cmd(OtKeymgrState *s);
static void ot_keymgr_continue_cmd(OtKeymgrState *s);
static void ot_keymgr_send_kmac_chunk(OtKeymgrState *s);
static void ot_keymgr_start_kmac(OtKeymgrState *s, const uint8_t *key,
                                 size_t key_len, const uint8_t *msg,
                                 size_t msg_len);

struct OtKeymgrState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    IbexIRQ alerts[PARAM_NUM_ALERTS];
    IbexIRQ op_done_irq;

    uint32_t *regs;
    OtKeymgrFsmState state;
    bool kmac_busy;
    uint8_t kmac_digest[KEYMGR_KEY_BYTES];
    OtKeymgrOperation current_op;

    const uint8_t *kmac_key_data;
    size_t kmac_key_len;
    const uint8_t *kmac_msg_data;
    size_t kmac_msg_len;
    size_t kmac_msg_sent;

    uint8_t creator_key[KEYMGR_KEY_BYTES];
    uint8_t owner_int_key[KEYMGR_KEY_BYTES];
    uint8_t owner_key[KEYMGR_KEY_BYTES];

    OtFlashState *flash_ctrl;
    OtLcCtrlState *lc_ctrl;
    OtOTPState *otp_ctrl;
    OtKMACState *kmac;
    uint8_t kmac_app_id;
};

static void ot_keymgr_update_working_state(OtKeymgrState *s)
{
    uint32_t working_state;

    switch (s->state) {
    case KM_STATE_RESET:
        working_state = 0; // StReset
        break;
    case KM_STATE_INIT:
        working_state = 1; // StInit
        break;
    case KM_STATE_CREATOR_ROOT_KEY:
        working_state = 2; // StCreatorRootKey
        break;
    case KM_STATE_OWNER_INTERMEDIATE_KEY:
        working_state = 3; // StOwnerIntKey
        break;
    case KM_STATE_OWNER_KEY:
        working_state = 4; // StOwnerKey
        break;
    case KM_STATE_DISABLED:
        working_state = 5; // StDisabled
        break;
    case KM_STATE_WIPE:
    case KM_STATE_INVALID:
    default:
        working_state = 6; // StInvalid
        break;
    }
    s->regs[R_WORKING_STATE] = working_state;
}

static void ot_keymgr_update_irq(OtKeymgrState *s)
{
    ibex_irq_set(&s->op_done_irq,
                 (s->regs[R_OP_STATUS] == 2 || s->regs[R_OP_STATUS] == 3));
}

static void ot_keymgr_update_alert(OtKeymgrState *s)
{
    bool alert = s->regs[R_ERR_CODE] || s->regs[R_FAULT_STATUS];
    ibex_irq_set(&s->alerts[0], alert);
    ibex_irq_set(&s->alerts[1], s->regs[R_FAULT_STATUS] != 0);
}

static uint64_t ot_keymgr_regs_read(void *opaque, hwaddr addr, unsigned size)
{
    OtKeymgrState *s = opaque;
    uint32_t val32;

    hwaddr reg = R32_OFF(addr);

    switch (reg) {
    case R_CFG_REGWEN:
    case R_START:
    case R_CONTROL_SHADOWED:
    case R_SIDELOAD_CLEAR:
    case R_RESEED_INTERVAL_REGWEN:
    case R_RESEED_INTERVAL_SHADOWED:
    case R_SW_BINDING_REGWEN:
    case R_SEALING_SW_BINDING_0:
    case R_SEALING_SW_BINDING_1:
    case R_SEALING_SW_BINDING_2:
    case R_SEALING_SW_BINDING_3:
    case R_SEALING_SW_BINDING_4:
    case R_SEALING_SW_BINDING_5:
    case R_SEALING_SW_BINDING_6:
    case R_SEALING_SW_BINDING_7:
    case R_ATTEST_SW_BINDING_0:
    case R_ATTEST_SW_BINDING_1:
    case R_ATTEST_SW_BINDING_2:
    case R_ATTEST_SW_BINDING_3:
    case R_ATTEST_SW_BINDING_4:
    case R_ATTEST_SW_BINDING_5:
    case R_ATTEST_SW_BINDING_6:
    case R_ATTEST_SW_BINDING_7:
    case R_SALT_0:
    case R_SALT_1:
    case R_SALT_2:
    case R_SALT_3:
    case R_SALT_4:
    case R_SALT_5:
    case R_SALT_6:
    case R_SALT_7:
    case R_KEY_VERSION_0:
    case R_MAX_CREATOR_KEY_VER_REGWEN:
    case R_MAX_CREATOR_KEY_VER_SHADOWED:
    case R_MAX_OWNER_INT_KEY_VER_REGWEN:
    case R_MAX_OWNER_INT_KEY_VER_SHADOWED:
    case R_MAX_OWNER_KEY_VER_REGWEN:
    case R_MAX_OWNER_KEY_VER_SHADOWED:
    case R_SW_SHARE0_OUTPUT_0:
    case R_SW_SHARE0_OUTPUT_1:
    case R_SW_SHARE0_OUTPUT_2:
    case R_SW_SHARE0_OUTPUT_3:
    case R_SW_SHARE0_OUTPUT_4:
    case R_SW_SHARE0_OUTPUT_5:
    case R_SW_SHARE0_OUTPUT_6:
    case R_SW_SHARE0_OUTPUT_7:
    case R_SW_SHARE1_OUTPUT_0:
    case R_SW_SHARE1_OUTPUT_1:
    case R_SW_SHARE1_OUTPUT_2:
    case R_SW_SHARE1_OUTPUT_3:
    case R_SW_SHARE1_OUTPUT_4:
    case R_SW_SHARE1_OUTPUT_5:
    case R_SW_SHARE1_OUTPUT_6:
    case R_SW_SHARE1_OUTPUT_7:
    case R_WORKING_STATE:
    case R_OP_STATUS:
    case R_ERR_CODE:
    case R_FAULT_STATUS:
    case R_DEBUG:
        val32 = s->regs[reg];
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Bad offset 0x%" HWADDR_PRIx "\n", __func__, addr);
        val32 = 0;
        break;
    }

    return val32;
}

static void ot_keymgr_regs_write(void *opaque, hwaddr addr, uint64_t value,
                                 unsigned size)
{
    OtKeymgrState *s = opaque;

    hwaddr reg = R32_OFF(addr);
    uint32_t value32 = value;

    switch (reg) {
    case R_START:
        s->regs[reg] = value32;
        if (value32) {
            ot_keymgr_process_cmd(s);
        }
        break;
    case R_CONTROL_SHADOWED:
        s->regs[reg] = value32;
        break;
    case R_SIDELOAD_CLEAR:
        s->regs[reg] = value32;
        break;
    case R_RESEED_INTERVAL_SHADOWED:
        s->regs[reg] = value32;
        break;
    case R_SEALING_SW_BINDING_0:
    case R_SEALING_SW_BINDING_1:
    case R_SEALING_SW_BINDING_2:
    case R_SEALING_SW_BINDING_3:
    case R_SEALING_SW_BINDING_4:
    case R_SEALING_SW_BINDING_5:
    case R_SEALING_SW_BINDING_6:
    case R_SEALING_SW_BINDING_7:
    case R_ATTEST_SW_BINDING_0:
    case R_ATTEST_SW_BINDING_1:
    case R_ATTEST_SW_BINDING_2:
    case R_ATTEST_SW_BINDING_3:
    case R_ATTEST_SW_BINDING_4:
    case R_ATTEST_SW_BINDING_5:
    case R_ATTEST_SW_BINDING_6:
    case R_ATTEST_SW_BINDING_7:
    case R_SALT_0:
    case R_SALT_1:
    case R_SALT_2:
    case R_SALT_3:
    case R_SALT_4:
    case R_SALT_5:
    case R_SALT_6:
    case R_SALT_7:
    case R_KEY_VERSION_0:
        s->regs[reg] = value32;
        break;
    case R_MAX_CREATOR_KEY_VER_SHADOWED:
    case R_MAX_OWNER_INT_KEY_VER_SHADOWED:
    case R_MAX_OWNER_KEY_VER_SHADOWED:
        s->regs[reg] = value32;
        break;
    case R_CFG_REGWEN:
    case R_RESEED_INTERVAL_REGWEN:
    case R_SW_BINDING_REGWEN:
    case R_MAX_CREATOR_KEY_VER_REGWEN:
    case R_MAX_OWNER_INT_KEY_VER_REGWEN:
    case R_MAX_OWNER_KEY_VER_REGWEN:
    case R_WORKING_STATE:
    case R_OP_STATUS:
    case R_ERR_CODE:
    case R_FAULT_STATUS:
    case R_DEBUG:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Write to read-only register 0x%" HWADDR_PRIx "\n",
                      __func__, addr);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: Bad offset 0x%" HWADDR_PRIx "\n", __func__, addr);
        break;
    }
}

static const MemoryRegionOps ot_keymgr_regs_ops = {
    .read = &ot_keymgr_regs_read,
    .write = &ot_keymgr_regs_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4u,
        .max_access_size = 4u,
    },
};

static void ot_keymgr_reset(DeviceState *dev)
{
    OtKeymgrState *s = OT_KEYMGR(dev);

    memset(s->regs, 0, REGS_SIZE);
    s->regs[R_CFG_REGWEN] = 0x1u;
    s->regs[R_CONTROL_SHADOWED] = 0x1u << 4u;
    s->regs[R_RESEED_INTERVAL_REGWEN] = 0x1u;
    s->regs[R_RESEED_INTERVAL_SHADOWED] = 0x100u;
    s->regs[R_SW_BINDING_REGWEN] = 0x1u;
    s->regs[R_MAX_CREATOR_KEY_VER_REGWEN] = 0x1u;
    s->regs[R_MAX_OWNER_INT_KEY_VER_REGWEN] = 0x1u;
    s->regs[R_MAX_OWNER_KEY_VER_REGWEN] = 0x1u;
    s->regs[R_MAX_OWNER_INT_KEY_VER_SHADOWED] = 0x1u;

    s->state = KM_STATE_RESET;
    s->current_op = KM_OP_NONE;
    s->kmac_busy = false;
    ot_keymgr_update_working_state(s);
}

/*
 * Checks if a value is not all 0s or all 1s.
 */
static bool valid_chk(const uint8_t *data, size_t len)
{
    bool all_zeros = true;
    bool all_ones = true;

    for (size_t i = 0; i < len; i++) {
        if (data[i] != 0x00) {
            all_zeros = false;
        }
        if (data[i] != 0xff) {
            all_ones = false;
        }
    }
    return !all_zeros && !all_ones;
}

static bool ot_keymgr_check_inputs(OtKeymgrState *s)
{
    // For now, assume they are valid (not all 0s or all 1s).
    uint8_t creator_seed[KEYMGR_KEY_BYTES] = { 0x1 };
    uint8_t owner_seed[KEYMGR_KEY_BYTES] = { 0x1 };
    // From keymgr.hjson DevIdWidth is 256 bits (32 bytes).
    uint8_t dev_id[32u] = { 0x1 };
    // From keymgr.hjson HealthStateWidth is 256 bits (32 bytes).
    uint8_t health_state[32u] = { 0x1 };
    bool inputs_ok = true;

    if (!valid_chk(creator_seed, sizeof(creator_seed))) {
        s->regs[R_DEBUG] =
            FIELD_DP32(s->regs[R_DEBUG], DEBUG, INVALID_CREATOR_SEED, 1u);
        inputs_ok = false;
    }

    if (!valid_chk(owner_seed, sizeof(owner_seed))) {
        s->regs[R_DEBUG] =
            FIELD_DP32(s->regs[R_DEBUG], DEBUG, INVALID_OWNER_SEED, 1u);
        inputs_ok = false;
    }

    if (!valid_chk(dev_id, sizeof(dev_id))) {
        s->regs[R_DEBUG] =
            FIELD_DP32(s->regs[R_DEBUG], DEBUG, INVALID_DEV_ID, 1u);
        inputs_ok = false;
    }

    if (!valid_chk(health_state, sizeof(health_state))) {
        s->regs[R_DEBUG] =
            FIELD_DP32(s->regs[R_DEBUG], DEBUG, INVALID_HEALTH_STATE, 1u);
        inputs_ok = false;
    }

    // Key version check
    uint32_t key_version = s->regs[R_KEY_VERSION_0];
    uint32_t max_key_version;

    switch (s->state) {
    case KM_STATE_CREATOR_ROOT_KEY:
        max_key_version = s->regs[R_MAX_CREATOR_KEY_VER_SHADOWED];
        if (key_version > max_key_version) {
            s->regs[R_DEBUG] =
                FIELD_DP32(s->regs[R_DEBUG], DEBUG, INVALID_KEY_VERSION, 1u);
            inputs_ok = false;
        }
        break;
    case KM_STATE_OWNER_INTERMEDIATE_KEY:
        max_key_version = s->regs[R_MAX_OWNER_INT_KEY_VER_SHADOWED];
        if (key_version > max_key_version) {
            s->regs[R_DEBUG] =
                FIELD_DP32(s->regs[R_DEBUG], DEBUG, INVALID_KEY_VERSION, 1u);
            inputs_ok = false;
        }
        break;
    case KM_STATE_OWNER_KEY:
        max_key_version = s->regs[R_MAX_OWNER_KEY_VER_SHADOWED];
        if (key_version > max_key_version) {
            s->regs[R_DEBUG] =
                FIELD_DP32(s->regs[R_DEBUG], DEBUG, INVALID_KEY_VERSION, 1u);
            inputs_ok = false;
        }
        break;
    default:
        // No key version check in other states
        break;
    }

    if (!inputs_ok) {
        s->regs[R_ERR_CODE] =
            FIELD_DP32(s->regs[R_ERR_CODE], ERR_CODE, INVALID_KMAC_INPUT, 1u);
        s->state = KM_STATE_WIPE;
        ot_keymgr_update_alert(s);
    }

    return inputs_ok;
}

static void ot_keymgr_op_advance(OtKeymgrState *s)
{
    switch (s->state) {
    case KM_STATE_RESET:
        s->state = KM_STATE_INIT;
        break;
    case KM_STATE_INIT: {
        uint8_t root_key[KEYMGR_KEY_BYTES] = { 0x1 };
        uint8_t *msg = (uint8_t *)&s->regs[R_SALT_0];
        ot_keymgr_start_kmac(s, root_key, sizeof(root_key), msg,
                             KEYMGR_SALT_BYTES);
        break;
    }
    case KM_STATE_CREATOR_ROOT_KEY: {
        uint8_t *msg = (uint8_t *)&s->regs[R_SALT_0];
        ot_keymgr_start_kmac(s, s->creator_key, sizeof(s->creator_key), msg,
                             KEYMGR_SALT_BYTES);
        break;
    }
    case KM_STATE_OWNER_INTERMEDIATE_KEY: {
        uint8_t *msg = (uint8_t *)&s->regs[R_SEALING_SW_BINDING_0];
        ot_keymgr_start_kmac(s, s->owner_int_key, sizeof(s->owner_int_key),
                             msg, KEYMGR_SW_BINDING_BYTES);
        break;
    }
    case KM_STATE_OWNER_KEY:
        s->state = KM_STATE_DISABLED;
        break;
    default:
        break;
    }
}

static void ot_keymgr_op_generate_id(OtKeymgrState *s, const uint8_t *key)
{
    const uint8_t *identity_seed;

    switch (s->state) {
    case KM_STATE_CREATOR_ROOT_KEY:
        identity_seed = RND_CNST_CREATOR_IDENTITY_SEED;
        break;
    case KM_STATE_OWNER_INTERMEDIATE_KEY:
        identity_seed = RND_CNST_OWNER_INT_IDENTITY_SEED;
        break;
    case KM_STATE_OWNER_KEY:
    default:
        identity_seed = RND_CNST_OWNER_IDENTITY_SEED;
        break;
    }
    ot_keymgr_start_kmac(s, key, KEYMGR_KEY_BYTES, identity_seed,
                         KEYMGR_KEY_BYTES);
}

static void ot_keymgr_op_generate_output(OtKeymgrState *s, const uint8_t *key,
                                       OtKeymgrOperation op)
{
    uint8_t msg[KEYMGR_GEN_DATA_BYTES];
    const uint8_t *output_seed;
    const uint8_t *dest_seed;
    uint32_t dest_sel =
        FIELD_EX32(s->regs[R_CONTROL_SHADOWED], CONTROL_SHADOWED, DEST_SEL);

    if (op == KM_OP_GENERATE_SW_OUTPUT) {
        output_seed = RND_CNST_SOFT_OUTPUT_SEED;
    } else {
        output_seed = RND_CNST_HARD_OUTPUT_SEED;
    }

    switch (dest_sel) {
    case 0: // Aes
        dest_seed = RND_CNST_AES_SEED;
        break;
    case 1: // Kmac
        dest_seed = RND_CNST_KMAC_SEED;
        break;
    case 2: // Otbn
        dest_seed = RND_CNST_OTBN_SEED;
        break;
    default:
        dest_seed = RND_CNST_NONE_SEED;
        break;
    }

    memcpy(&msg[0], output_seed, 32);
    memcpy(&msg[32], dest_seed, 32);
    memcpy(&msg[64], &s->regs[R_SALT_0], 32);
    memcpy(&msg[96], &s->regs[R_KEY_VERSION_0], 32);

    ot_keymgr_start_kmac(s, key, KEYMGR_KEY_BYTES, msg, sizeof(msg));
}

static void ot_keymgr_op_disable(OtKeymgrState *s)
{
    s->state = KM_STATE_DISABLED;
}

static void ot_keymgr_process_cmd(OtKeymgrState *s)
{
    if (s->state == KM_STATE_WIPE) {
        memset(s->creator_key, 0, sizeof(s->creator_key));
        memset(s->owner_int_key, 0, sizeof(s->owner_int_key));
        memset(s->owner_key, 0, sizeof(s->owner_key));
        s->state = KM_STATE_INVALID;
        ot_keymgr_update_working_state(s);
        s->regs[R_OP_STATUS] = 3; // DoneError
        ot_keymgr_update_irq(s);
        return;
    }

    if (!ot_keymgr_check_inputs(s)) {
        s->regs[R_OP_STATUS] = 3; // DoneError
        ot_keymgr_update_irq(s);
        s->state = KM_STATE_WIPE;
        ot_keymgr_update_working_state(s);
        return;
    }

    s->current_op = (OtKeymgrOperation)FIELD_EX32(s->regs[R_CONTROL_SHADOWED],
                                                 CONTROL_SHADOWED, OPERATION);
    s->regs[R_OP_STATUS] = 1; // WIP
    bool sync_op = false;

    const uint8_t *key = NULL;
    switch (s->state) {
    case KM_STATE_CREATOR_ROOT_KEY:
        key = s->creator_key;
        break;
    case KM_STATE_OWNER_INTERMEDIATE_KEY:
        key = s->owner_int_key;
        break;
    case KM_STATE_OWNER_KEY:
        key = s->owner_key;
        break;
    default:
        break;
    }

    switch (s->current_op) {
    case KM_OP_ADVANCE:
        if (s->state == KM_STATE_RESET || s->state == KM_STATE_OWNER_KEY ||
            s->state == KM_STATE_DISABLED) {
            sync_op = true;
        }
        ot_keymgr_op_advance(s);
        break;
    case KM_OP_GENERATE_ID:
        if (key) {
            ot_keymgr_op_generate_id(s, key);
        } else {
            s->regs[R_ERR_CODE] =
                FIELD_DP32(s->regs[R_ERR_CODE], ERR_CODE, INVALID_OP, 1u);
            s->state = KM_STATE_WIPE;
        }
        break;
    case KM_OP_GENERATE_SW_OUTPUT:
    case KM_OP_GENERATE_HW_OUTPUT:
        if (key) {
            ot_keymgr_op_generate_output(s, key, s->current_op);
        } else {
            s->regs[R_ERR_CODE] =
                FIELD_DP32(s->regs[R_ERR_CODE], ERR_CODE, INVALID_OP, 1u);
            s->state = KM_STATE_WIPE;
        }
        break;
    case KM_OP_DISABLE:
        sync_op = true;
        ot_keymgr_op_disable(s);
        break;
    default:
        s->regs[R_ERR_CODE] =
            FIELD_DP32(s->regs[R_ERR_CODE], ERR_CODE, INVALID_OP, 1u);
        s->state = KM_STATE_WIPE;
        break;
    }

    if (s->state == KM_STATE_WIPE) {
        ot_keymgr_update_alert(s);
        ot_keymgr_process_cmd(s);
    } else if (sync_op) {
        s->regs[R_OP_STATUS] = 2; // DoneSuccess
        ot_keymgr_update_working_state(s);
        ot_keymgr_update_irq(s);
    }
}

static void ot_keymgr_continue_cmd(OtKeymgrState *s)
{
    switch (s->current_op) {
    case KM_OP_ADVANCE:
        switch (s->state) {
        case KM_STATE_INIT:
            memcpy(s->creator_key, s->kmac_digest, sizeof(s->creator_key));
            s->state = KM_STATE_CREATOR_ROOT_KEY;
            break;
        case KM_STATE_CREATOR_ROOT_KEY:
            memcpy(s->owner_int_key, s->kmac_digest, sizeof(s->owner_int_key));
            s->state = KM_STATE_OWNER_INTERMEDIATE_KEY;
            break;
        case KM_STATE_OWNER_INTERMEDIATE_KEY:
            memcpy(s->owner_key, s->kmac_digest, sizeof(s->owner_key));
            s->state = KM_STATE_OWNER_KEY;
            break;
        default:
            // Should not be reachable
            break;
        }
        break;
    case KM_OP_GENERATE_ID:
        // ID is not stored in the model, operation is effectively a no-op
        // after KMAC.
        break;
    case KM_OP_GENERATE_SW_OUTPUT:
        memcpy(&s->regs[R_SW_SHARE0_OUTPUT_0], s->kmac_digest,
               sizeof(s->kmac_digest));
        memset(&s->regs[R_SW_SHARE1_OUTPUT_0], 0, sizeof(s->kmac_digest));
        break;
    case KM_OP_GENERATE_HW_OUTPUT: {
        uint32_t dest_sel =
            FIELD_EX32(s->regs[R_CONTROL_SHADOWED], CONTROL_SHADOWED, DEST_SEL);
        qemu_log_mask(LOG_UNIMP,
                      "%s: Sideloading for dest %d not implemented\n",
                      __func__, dest_sel);
        break;
    }
    case KM_OP_DISABLE:
    case KM_OP_NONE:
    default:
        // Should not be reachable
        break;
    }

    s->current_op = KM_OP_NONE;
    ot_keymgr_update_working_state(s);
    s->regs[R_OP_STATUS] = 2; // DoneSuccess
    ot_keymgr_update_irq(s);
}

static void ot_keymgr_start_kmac(OtKeymgrState *s, const uint8_t *key,
                                 size_t key_len, const uint8_t *msg,
                                 size_t msg_len)
{
    g_assert(!s->kmac_busy);

    s->kmac_busy = true;
    s->kmac_key_data = key;
    s->kmac_key_len = key_len;
    s->kmac_msg_data = msg;
    s->kmac_msg_len = msg_len;
    s->kmac_msg_sent = 0;

    ot_keymgr_send_kmac_chunk(s);
}

static void ot_keymgr_send_kmac_chunk(OtKeymgrState *s)
{
    OtKMACAppReq req;
    memset(&req, 0, sizeof(req));

    if (s->kmac_msg_sent == 0) {
        // First chunk, send key
        req.key = s->kmac_key_data;
        req.key_len = s->kmac_key_len;
    }

    size_t msg_left = s->kmac_msg_len - s->kmac_msg_sent;
    size_t to_send = MIN(msg_left, OT_KMAC_APP_MSG_BYTES);
    memcpy(req.msg_data, s->kmac_msg_data + s->kmac_msg_sent, to_send);
    req.msg_len = to_send;
    s->kmac_msg_sent += to_send;

    req.last = (s->kmac_msg_sent == s->kmac_msg_len);

    ot_kmac_app_request(s->kmac, s->kmac_app_id, &req);
}

static void ot_keymgr_kmac_done(void *opaque, const OtKMACAppRsp *rsp)
{
    OtKeymgrState *s = opaque;

    if (!rsp->done) {
        // Not the final response, send next chunk.
        ot_keymgr_send_kmac_chunk(s);
        return;
    }

    g_assert(s->kmac_busy);

    memcpy(s->kmac_digest, rsp->digest_share0, sizeof(s->kmac_digest));

    s->kmac_busy = false;
    ot_keymgr_continue_cmd(s);
}

static void ot_keymgr_realize(DeviceState *dev, Error **errp)
{
    OtKeymgrState *s = OT_KEYMGR(dev);
    (void)errp;

    const OtKMACAppCfg kmac_cfg =
        OT_KMAC_CONFIG(KMAC, 256, "KMAC", "KEYMGR");

    ot_kmac_connect_app(s->kmac, s->kmac_app_id, &kmac_cfg,
                        &ot_keymgr_kmac_done, s);
}

static Property ot_keymgr_properties[] = {
    DEFINE_PROP_LINK("flash-ctrl", OtKeymgrState, flash_ctrl, TYPE_OT_FLASH,
                     OtFlashState *),
    DEFINE_PROP_LINK("lc-ctrl", OtKeymgrState, lc_ctrl, TYPE_OT_LC_CTRL,
                     OtLcCtrlState *),
    DEFINE_PROP_LINK("otp-ctrl", OtKeymgrState, otp_ctrl, TYPE_OT_OTP,
                     OtOTPState *),
    DEFINE_PROP_LINK("kmac", OtKeymgrState, kmac, TYPE_OT_KMAC, OtKMACState *),
    DEFINE_PROP_UINT8("kmac-app-id", OtKeymgrState, kmac_app_id, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void ot_keymgr_init(Object *obj)
{
    OtKeymgrState *s = OT_KEYMGR(obj);

    s->regs = g_new0(uint32_t, REGS_COUNT);

    memory_region_init_io(&s->mmio, obj, &ot_keymgr_regs_ops, s,
                          TYPE_OT_KEYMGR ".regs", REGS_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mmio);

    for (unsigned i = 0; i < PARAM_NUM_ALERTS; i++) {
        ibex_qdev_init_irq(obj, &s->alerts[i], OT_DEVICE_ALERT);
    }
    ibex_qdev_init_irq(obj, &s->op_done_irq, OT_DEVICE_ALERT);
}

static void ot_keymgr_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    (void)data;

    dc->realize = &ot_keymgr_realize;
    device_class_set_legacy_reset(dc, &ot_keymgr_reset);
    device_class_set_props(dc, ot_keymgr_properties);
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo ot_keymgr_info = {
    .name = TYPE_OT_KEYMGR,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(OtKeymgrState),
    .instance_init = &ot_keymgr_init,
    .class_init = &ot_keymgr_class_init,
};

static void ot_keymgr_register_types(void)
{
    type_register_static(&ot_keymgr_info);
}

type_init(ot_keymgr_register_types);
