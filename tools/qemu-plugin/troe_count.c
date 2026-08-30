/*
 * Guest-work counter for cross-guest comparison under QEMU TCG.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This file is the one component of TROE that is not Apache-2.0. It includes
 * QEMU's <qemu-plugin.h>, which is GPL-2.0-or-later, so it carries the same
 * licence. It is a host-side measurement tool loaded by QEMU through dlopen;
 * no part of it is linked into the kernel, the KEX applications, the SDK, or
 * any shipped image. See THIRD_PARTY.md.
 *
 * Wall-clock time alone cannot separate "executed more instructions", which is
 * a code-generation difference in the application, from "the same instructions
 * cost more", which is a difference in the surrounding environment. This
 * counts executed guest instructions, translation blocks, and memory accesses,
 * split into an application address window and everything else, so the two can
 * be told apart.
 *
 * Arguments (optional, decimal or 0x-prefixed):
 *   user_lo=ADDRESS   inclusive start of the application window
 *   user_hi=ADDRESS   exclusive end of the application window
 *
 * Without arguments every instruction is reported in the "other" bucket.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct TroeCounters {
    uint64_t user_instructions;
    uint64_t user_blocks;
    uint64_t user_reads;
    uint64_t user_writes;
    uint64_t other_instructions;
    uint64_t other_blocks;
    uint64_t other_reads;
    uint64_t other_writes;
} TroeCounters;

static struct qemu_plugin_scoreboard *counters;
static uint64_t user_low;
static uint64_t user_high;

#define TROE_FIELD(member) \
    qemu_plugin_scoreboard_u64_in_struct(counters, TroeCounters, member)

static void translate(struct qemu_plugin_tb *block, void *context)
{
    size_t count = qemu_plugin_tb_n_insns(block);
    uint64_t address = qemu_plugin_tb_vaddr(block);
    int user = address >= user_low && address < user_high;
    (void)context;
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        block, QEMU_PLUGIN_INLINE_ADD_U64,
        user ? TROE_FIELD(user_instructions) : TROE_FIELD(other_instructions),
        count);
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        block, QEMU_PLUGIN_INLINE_ADD_U64,
        user ? TROE_FIELD(user_blocks) : TROE_FIELD(other_blocks), 1);
    for (size_t index = 0; index < count; ++index) {
        struct qemu_plugin_insn *instruction =
            qemu_plugin_tb_get_insn(block, index);
        qemu_plugin_register_vcpu_mem_inline_per_vcpu(
            instruction, QEMU_PLUGIN_MEM_R, QEMU_PLUGIN_INLINE_ADD_U64,
            user ? TROE_FIELD(user_reads) : TROE_FIELD(other_reads), 1);
        qemu_plugin_register_vcpu_mem_inline_per_vcpu(
            instruction, QEMU_PLUGIN_MEM_W, QEMU_PLUGIN_INLINE_ADD_U64,
            user ? TROE_FIELD(user_writes) : TROE_FIELD(other_writes), 1);
    }
}

static void report(void *context)
{
    char line[512];
    (void)context;
    snprintf(line, sizeof(line),
             "guest-work user_instructions=%" PRIu64
             " user_blocks=%" PRIu64
             " user_reads=%" PRIu64
             " user_writes=%" PRIu64
             " other_instructions=%" PRIu64
             " other_blocks=%" PRIu64
             " other_reads=%" PRIu64
             " other_writes=%" PRIu64 "\n",
             qemu_plugin_u64_sum(TROE_FIELD(user_instructions)),
             qemu_plugin_u64_sum(TROE_FIELD(user_blocks)),
             qemu_plugin_u64_sum(TROE_FIELD(user_reads)),
             qemu_plugin_u64_sum(TROE_FIELD(user_writes)),
             qemu_plugin_u64_sum(TROE_FIELD(other_instructions)),
             qemu_plugin_u64_sum(TROE_FIELD(other_blocks)),
             qemu_plugin_u64_sum(TROE_FIELD(other_reads)),
             qemu_plugin_u64_sum(TROE_FIELD(other_writes)));
    qemu_plugin_outs(line);
    qemu_plugin_scoreboard_free(counters);
}

static int parse_window(const char *argument)
{
    char *end = NULL;
    uint64_t value;
    const char *text;
    if (strncmp(argument, "user_lo=", 8) == 0 ||
        strncmp(argument, "user_hi=", 8) == 0) {
        text = argument + 8;
    } else {
        return -1;
    }
    if (*text == '\0') {
        return -1;
    }
    value = strtoull(text, &end, 0);
    if (end == NULL || *end != '\0') {
        return -1;
    }
    if (argument[5] == 'l') {
        user_low = value;
    } else {
        user_high = value;
    }
    return 0;
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    (void)info;
    for (int index = 0; index < argc; ++index) {
        if (parse_window(argv[index]) != 0) {
            fprintf(stderr,
                    "troe_count: expected user_lo=ADDRESS or user_hi=ADDRESS, "
                    "got: %s\n",
                    argv[index]);
            return -1;
        }
    }
    if (user_low > user_high) {
        fprintf(stderr, "troe_count: user_lo must not exceed user_hi\n");
        return -1;
    }
    counters = qemu_plugin_scoreboard_new(sizeof(TroeCounters));
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate, NULL);
    qemu_plugin_register_atexit_cb(id, report, NULL);
    return 0;
}
