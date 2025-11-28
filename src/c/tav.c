/*
 * TAV Clock Cryptography v0.9
 * Copyright (C) 2025 Carlos Alberto Terencio de Bastos
 * License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto
 *
 * TAV CLOCK CRYPTOGRAPHY v0.9 - C Implementation
 * ===============================================
 * 
 * A stateful cryptographic system based on ephemeral structure
 * and continuous physical entropy.
 * 
 * Features:
 * - Lookup tables ROT_LEFT pre-computed
 * - Automatic checkpoint every 10,000 transactions
 * - Encrypted checkpoint (self-protecting)
 * - Hardware change detection
 * - Threat management with dynamic escalation
 */

#include "tav.h"
#include <string.h>
#include <stdlib.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>
#endif

/* ============================================================================
 * LOOKUP TABLE ROT_LEFT PRÃ‰-COMPUTADA
 * ============================================================================ */

const uint8_t TAV_ROT_LEFT[8][256] = {
    /* rot=0 (identidade) */
    {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
        0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
        0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
        0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
        0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,
        0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
        0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,
        0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
    },
    /* rot=1 */
    {
        0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
        0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
        0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
        0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
        0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
        0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
        0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
        0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
        0x01,0x03,0x05,0x07,0x09,0x0b,0x0d,0x0f,0x11,0x13,0x15,0x17,0x19,0x1b,0x1d,0x1f,
        0x21,0x23,0x25,0x27,0x29,0x2b,0x2d,0x2f,0x31,0x33,0x35,0x37,0x39,0x3b,0x3d,0x3f,
        0x41,0x43,0x45,0x47,0x49,0x4b,0x4d,0x4f,0x51,0x53,0x55,0x57,0x59,0x5b,0x5d,0x5f,
        0x61,0x63,0x65,0x67,0x69,0x6b,0x6d,0x6f,0x71,0x73,0x75,0x77,0x79,0x7b,0x7d,0x7f,
        0x81,0x83,0x85,0x87,0x89,0x8b,0x8d,0x8f,0x91,0x93,0x95,0x97,0x99,0x9b,0x9d,0x9f,
        0xa1,0xa3,0xa5,0xa7,0xa9,0xab,0xad,0xaf,0xb1,0xb3,0xb5,0xb7,0xb9,0xbb,0xbd,0xbf,
        0xc1,0xc3,0xc5,0xc7,0xc9,0xcb,0xcd,0xcf,0xd1,0xd3,0xd5,0xd7,0xd9,0xdb,0xdd,0xdf,
        0xe1,0xe3,0xe5,0xe7,0xe9,0xeb,0xed,0xef,0xf1,0xf3,0xf5,0xf7,0xf9,0xfb,0xfd,0xff
    },
    /* rot=2 */
    {
        0x00,0x04,0x08,0x0c,0x10,0x14,0x18,0x1c,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,
        0x40,0x44,0x48,0x4c,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x6c,0x70,0x74,0x78,0x7c,
        0x80,0x84,0x88,0x8c,0x90,0x94,0x98,0x9c,0xa0,0xa4,0xa8,0xac,0xb0,0xb4,0xb8,0xbc,
        0xc0,0xc4,0xc8,0xcc,0xd0,0xd4,0xd8,0xdc,0xe0,0xe4,0xe8,0xec,0xf0,0xf4,0xf8,0xfc,
        0x01,0x05,0x09,0x0d,0x11,0x15,0x19,0x1d,0x21,0x25,0x29,0x2d,0x31,0x35,0x39,0x3d,
        0x41,0x45,0x49,0x4d,0x51,0x55,0x59,0x5d,0x61,0x65,0x69,0x6d,0x71,0x75,0x79,0x7d,
        0x81,0x85,0x89,0x8d,0x91,0x95,0x99,0x9d,0xa1,0xa5,0xa9,0xad,0xb1,0xb5,0xb9,0xbd,
        0xc1,0xc5,0xc9,0xcd,0xd1,0xd5,0xd9,0xdd,0xe1,0xe5,0xe9,0xed,0xf1,0xf5,0xf9,0xfd,
        0x02,0x06,0x0a,0x0e,0x12,0x16,0x1a,0x1e,0x22,0x26,0x2a,0x2e,0x32,0x36,0x3a,0x3e,
        0x42,0x46,0x4a,0x4e,0x52,0x56,0x5a,0x5e,0x62,0x66,0x6a,0x6e,0x72,0x76,0x7a,0x7e,
        0x82,0x86,0x8a,0x8e,0x92,0x96,0x9a,0x9e,0xa2,0xa6,0xaa,0xae,0xb2,0xb6,0xba,0xbe,
        0xc2,0xc6,0xca,0xce,0xd2,0xd6,0xda,0xde,0xe2,0xe6,0xea,0xee,0xf2,0xf6,0xfa,0xfe,
        0x03,0x07,0x0b,0x0f,0x13,0x17,0x1b,0x1f,0x23,0x27,0x2b,0x2f,0x33,0x37,0x3b,0x3f,
        0x43,0x47,0x4b,0x4f,0x53,0x57,0x5b,0x5f,0x63,0x67,0x6b,0x6f,0x73,0x77,0x7b,0x7f,
        0x83,0x87,0x8b,0x8f,0x93,0x97,0x9b,0x9f,0xa3,0xa7,0xab,0xaf,0xb3,0xb7,0xbb,0xbf,
        0xc3,0xc7,0xcb,0xcf,0xd3,0xd7,0xdb,0xdf,0xe3,0xe7,0xeb,0xef,0xf3,0xf7,0xfb,0xff
    },
    /* rot=3 */
    {
        0x00,0x08,0x10,0x18,0x20,0x28,0x30,0x38,0x40,0x48,0x50,0x58,0x60,0x68,0x70,0x78,
        0x80,0x88,0x90,0x98,0xa0,0xa8,0xb0,0xb8,0xc0,0xc8,0xd0,0xd8,0xe0,0xe8,0xf0,0xf8,
        0x01,0x09,0x11,0x19,0x21,0x29,0x31,0x39,0x41,0x49,0x51,0x59,0x61,0x69,0x71,0x79,
        0x81,0x89,0x91,0x99,0xa1,0xa9,0xb1,0xb9,0xc1,0xc9,0xd1,0xd9,0xe1,0xe9,0xf1,0xf9,
        0x02,0x0a,0x12,0x1a,0x22,0x2a,0x32,0x3a,0x42,0x4a,0x52,0x5a,0x62,0x6a,0x72,0x7a,
        0x82,0x8a,0x92,0x9a,0xa2,0xaa,0xb2,0xba,0xc2,0xca,0xd2,0xda,0xe2,0xea,0xf2,0xfa,
        0x03,0x0b,0x13,0x1b,0x23,0x2b,0x33,0x3b,0x43,0x4b,0x53,0x5b,0x63,0x6b,0x73,0x7b,
        0x83,0x8b,0x93,0x9b,0xa3,0xab,0xb3,0xbb,0xc3,0xcb,0xd3,0xdb,0xe3,0xeb,0xf3,0xfb,
        0x04,0x0c,0x14,0x1c,0x24,0x2c,0x34,0x3c,0x44,0x4c,0x54,0x5c,0x64,0x6c,0x74,0x7c,
        0x84,0x8c,0x94,0x9c,0xa4,0xac,0xb4,0xbc,0xc4,0xcc,0xd4,0xdc,0xe4,0xec,0xf4,0xfc,
        0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d,0x45,0x4d,0x55,0x5d,0x65,0x6d,0x75,0x7d,
        0x85,0x8d,0x95,0x9d,0xa5,0xad,0xb5,0xbd,0xc5,0xcd,0xd5,0xdd,0xe5,0xed,0xf5,0xfd,
        0x06,0x0e,0x16,0x1e,0x26,0x2e,0x36,0x3e,0x46,0x4e,0x56,0x5e,0x66,0x6e,0x76,0x7e,
        0x86,0x8e,0x96,0x9e,0xa6,0xae,0xb6,0xbe,0xc6,0xce,0xd6,0xde,0xe6,0xee,0xf6,0xfe,
        0x07,0x0f,0x17,0x1f,0x27,0x2f,0x37,0x3f,0x47,0x4f,0x57,0x5f,0x67,0x6f,0x77,0x7f,
        0x87,0x8f,0x97,0x9f,0xa7,0xaf,0xb7,0xbf,0xc7,0xcf,0xd7,0xdf,0xe7,0xef,0xf7,0xff
    },
    /* rot=4 */
    {
        0x00,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,
        0x01,0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81,0x91,0xa1,0xb1,0xc1,0xd1,0xe1,0xf1,
        0x02,0x12,0x22,0x32,0x42,0x52,0x62,0x72,0x82,0x92,0xa2,0xb2,0xc2,0xd2,0xe2,0xf2,
        0x03,0x13,0x23,0x33,0x43,0x53,0x63,0x73,0x83,0x93,0xa3,0xb3,0xc3,0xd3,0xe3,0xf3,
        0x04,0x14,0x24,0x34,0x44,0x54,0x64,0x74,0x84,0x94,0xa4,0xb4,0xc4,0xd4,0xe4,0xf4,
        0x05,0x15,0x25,0x35,0x45,0x55,0x65,0x75,0x85,0x95,0xa5,0xb5,0xc5,0xd5,0xe5,0xf5,
        0x06,0x16,0x26,0x36,0x46,0x56,0x66,0x76,0x86,0x96,0xa6,0xb6,0xc6,0xd6,0xe6,0xf6,
        0x07,0x17,0x27,0x37,0x47,0x57,0x67,0x77,0x87,0x97,0xa7,0xb7,0xc7,0xd7,0xe7,0xf7,
        0x08,0x18,0x28,0x38,0x48,0x58,0x68,0x78,0x88,0x98,0xa8,0xb8,0xc8,0xd8,0xe8,0xf8,
        0x09,0x19,0x29,0x39,0x49,0x59,0x69,0x79,0x89,0x99,0xa9,0xb9,0xc9,0xd9,0xe9,0xf9,
        0x0a,0x1a,0x2a,0x3a,0x4a,0x5a,0x6a,0x7a,0x8a,0x9a,0xaa,0xba,0xca,0xda,0xea,0xfa,
        0x0b,0x1b,0x2b,0x3b,0x4b,0x5b,0x6b,0x7b,0x8b,0x9b,0xab,0xbb,0xcb,0xdb,0xeb,0xfb,
        0x0c,0x1c,0x2c,0x3c,0x4c,0x5c,0x6c,0x7c,0x8c,0x9c,0xac,0xbc,0xcc,0xdc,0xec,0xfc,
        0x0d,0x1d,0x2d,0x3d,0x4d,0x5d,0x6d,0x7d,0x8d,0x9d,0xad,0xbd,0xcd,0xdd,0xed,0xfd,
        0x0e,0x1e,0x2e,0x3e,0x4e,0x5e,0x6e,0x7e,0x8e,0x9e,0xae,0xbe,0xce,0xde,0xee,0xfe,
        0x0f,0x1f,0x2f,0x3f,0x4f,0x5f,0x6f,0x7f,0x8f,0x9f,0xaf,0xbf,0xcf,0xdf,0xef,0xff
    },
    /* rot=5 */
    {
        0x00,0x20,0x40,0x60,0x80,0xa0,0xc0,0xe0,0x01,0x21,0x41,0x61,0x81,0xa1,0xc1,0xe1,
        0x02,0x22,0x42,0x62,0x82,0xa2,0xc2,0xe2,0x03,0x23,0x43,0x63,0x83,0xa3,0xc3,0xe3,
        0x04,0x24,0x44,0x64,0x84,0xa4,0xc4,0xe4,0x05,0x25,0x45,0x65,0x85,0xa5,0xc5,0xe5,
        0x06,0x26,0x46,0x66,0x86,0xa6,0xc6,0xe6,0x07,0x27,0x47,0x67,0x87,0xa7,0xc7,0xe7,
        0x08,0x28,0x48,0x68,0x88,0xa8,0xc8,0xe8,0x09,0x29,0x49,0x69,0x89,0xa9,0xc9,0xe9,
        0x0a,0x2a,0x4a,0x6a,0x8a,0xaa,0xca,0xea,0x0b,0x2b,0x4b,0x6b,0x8b,0xab,0xcb,0xeb,
        0x0c,0x2c,0x4c,0x6c,0x8c,0xac,0xcc,0xec,0x0d,0x2d,0x4d,0x6d,0x8d,0xad,0xcd,0xed,
        0x0e,0x2e,0x4e,0x6e,0x8e,0xae,0xce,0xee,0x0f,0x2f,0x4f,0x6f,0x8f,0xaf,0xcf,0xef,
        0x10,0x30,0x50,0x70,0x90,0xb0,0xd0,0xf0,0x11,0x31,0x51,0x71,0x91,0xb1,0xd1,0xf1,
        0x12,0x32,0x52,0x72,0x92,0xb2,0xd2,0xf2,0x13,0x33,0x53,0x73,0x93,0xb3,0xd3,0xf3,
        0x14,0x34,0x54,0x74,0x94,0xb4,0xd4,0xf4,0x15,0x35,0x55,0x75,0x95,0xb5,0xd5,0xf5,
        0x16,0x36,0x56,0x76,0x96,0xb6,0xd6,0xf6,0x17,0x37,0x57,0x77,0x97,0xb7,0xd7,0xf7,
        0x18,0x38,0x58,0x78,0x98,0xb8,0xd8,0xf8,0x19,0x39,0x59,0x79,0x99,0xb9,0xd9,0xf9,
        0x1a,0x3a,0x5a,0x7a,0x9a,0xba,0xda,0xfa,0x1b,0x3b,0x5b,0x7b,0x9b,0xbb,0xdb,0xfb,
        0x1c,0x3c,0x5c,0x7c,0x9c,0xbc,0xdc,0xfc,0x1d,0x3d,0x5d,0x7d,0x9d,0xbd,0xdd,0xfd,
        0x1e,0x3e,0x5e,0x7e,0x9e,0xbe,0xde,0xfe,0x1f,0x3f,0x5f,0x7f,0x9f,0xbf,0xdf,0xff
    },
    /* rot=6 */
    {
        0x00,0x40,0x80,0xc0,0x01,0x41,0x81,0xc1,0x02,0x42,0x82,0xc2,0x03,0x43,0x83,0xc3,
        0x04,0x44,0x84,0xc4,0x05,0x45,0x85,0xc5,0x06,0x46,0x86,0xc6,0x07,0x47,0x87,0xc7,
        0x08,0x48,0x88,0xc8,0x09,0x49,0x89,0xc9,0x0a,0x4a,0x8a,0xca,0x0b,0x4b,0x8b,0xcb,
        0x0c,0x4c,0x8c,0xcc,0x0d,0x4d,0x8d,0xcd,0x0e,0x4e,0x8e,0xce,0x0f,0x4f,0x8f,0xcf,
        0x10,0x50,0x90,0xd0,0x11,0x51,0x91,0xd1,0x12,0x52,0x92,0xd2,0x13,0x53,0x93,0xd3,
        0x14,0x54,0x94,0xd4,0x15,0x55,0x95,0xd5,0x16,0x56,0x96,0xd6,0x17,0x57,0x97,0xd7,
        0x18,0x58,0x98,0xd8,0x19,0x59,0x99,0xd9,0x1a,0x5a,0x9a,0xda,0x1b,0x5b,0x9b,0xdb,
        0x1c,0x5c,0x9c,0xdc,0x1d,0x5d,0x9d,0xdd,0x1e,0x5e,0x9e,0xde,0x1f,0x5f,0x9f,0xdf,
        0x20,0x60,0xa0,0xe0,0x21,0x61,0xa1,0xe1,0x22,0x62,0xa2,0xe2,0x23,0x63,0xa3,0xe3,
        0x24,0x64,0xa4,0xe4,0x25,0x65,0xa5,0xe5,0x26,0x66,0xa6,0xe6,0x27,0x67,0xa7,0xe7,
        0x28,0x68,0xa8,0xe8,0x29,0x69,0xa9,0xe9,0x2a,0x6a,0xaa,0xea,0x2b,0x6b,0xab,0xeb,
        0x2c,0x6c,0xac,0xec,0x2d,0x6d,0xad,0xed,0x2e,0x6e,0xae,0xee,0x2f,0x6f,0xaf,0xef,
        0x30,0x70,0xb0,0xf0,0x31,0x71,0xb1,0xf1,0x32,0x72,0xb2,0xf2,0x33,0x73,0xb3,0xf3,
        0x34,0x74,0xb4,0xf4,0x35,0x75,0xb5,0xf5,0x36,0x76,0xb6,0xf6,0x37,0x77,0xb7,0xf7,
        0x38,0x78,0xb8,0xf8,0x39,0x79,0xb9,0xf9,0x3a,0x7a,0xba,0xfa,0x3b,0x7b,0xbb,0xfb,
        0x3c,0x7c,0xbc,0xfc,0x3d,0x7d,0xbd,0xfd,0x3e,0x7e,0xbe,0xfe,0x3f,0x7f,0xbf,0xff
    },
    /* rot=7 */
    {
        0x00,0x80,0x01,0x81,0x02,0x82,0x03,0x83,0x04,0x84,0x05,0x85,0x06,0x86,0x07,0x87,
        0x08,0x88,0x09,0x89,0x0a,0x8a,0x0b,0x8b,0x0c,0x8c,0x0d,0x8d,0x0e,0x8e,0x0f,0x8f,
        0x10,0x90,0x11,0x91,0x12,0x92,0x13,0x93,0x14,0x94,0x15,0x95,0x16,0x96,0x17,0x97,
        0x18,0x98,0x19,0x99,0x1a,0x9a,0x1b,0x9b,0x1c,0x9c,0x1d,0x9d,0x1e,0x9e,0x1f,0x9f,
        0x20,0xa0,0x21,0xa1,0x22,0xa2,0x23,0xa3,0x24,0xa4,0x25,0xa5,0x26,0xa6,0x27,0xa7,
        0x28,0xa8,0x29,0xa9,0x2a,0xaa,0x2b,0xab,0x2c,0xac,0x2d,0xad,0x2e,0xae,0x2f,0xaf,
        0x30,0xb0,0x31,0xb1,0x32,0xb2,0x33,0xb3,0x34,0xb4,0x35,0xb5,0x36,0xb6,0x37,0xb7,
        0x38,0xb8,0x39,0xb9,0x3a,0xba,0x3b,0xbb,0x3c,0xbc,0x3d,0xbd,0x3e,0xbe,0x3f,0xbf,
        0x40,0xc0,0x41,0xc1,0x42,0xc2,0x43,0xc3,0x44,0xc4,0x45,0xc5,0x46,0xc6,0x47,0xc7,
        0x48,0xc8,0x49,0xc9,0x4a,0xca,0x4b,0xcb,0x4c,0xcc,0x4d,0xcd,0x4e,0xce,0x4f,0xcf,
        0x50,0xd0,0x51,0xd1,0x52,0xd2,0x53,0xd3,0x54,0xd4,0x55,0xd5,0x56,0xd6,0x57,0xd7,
        0x58,0xd8,0x59,0xd9,0x5a,0xda,0x5b,0xdb,0x5c,0xdc,0x5d,0xdd,0x5e,0xde,0x5f,0xdf,
        0x60,0xe0,0x61,0xe1,0x62,0xe2,0x63,0xe3,0x64,0xe4,0x65,0xe5,0x66,0xe6,0x67,0xe7,
        0x68,0xe8,0x69,0xe9,0x6a,0xea,0x6b,0xeb,0x6c,0xec,0x6d,0xed,0x6e,0xee,0x6f,0xef,
        0x70,0xf0,0x71,0xf1,0x72,0xf2,0x73,0xf3,0x74,0xf4,0x75,0xf5,0x76,0xf6,0x77,0xf7,
        0x78,0xf8,0x79,0xf9,0x7a,0xfa,0x7b,0xfb,0x7c,0xfc,0x7d,0xfd,0x7e,0xfe,0x7f,0xff
    }
};

/* Constantes do Mixer */
const uint8_t TAV_CONST_AND[TAV_CONST_SIZE] = {
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF
};

const uint8_t TAV_CONST_OR[TAV_CONST_SIZE] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
};

/* ============================================================================
 * PRIMOS HARDCODED
 * ============================================================================ */

static const uint32_t PRIMES_BOX_1[] = {
    17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103
};
#define PRIMES_BOX_1_COUNT 21

static const uint32_t PRIMES_BOX_2[] = {
    107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
    191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269,
    271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359,
    367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449,
    457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541
};
#define PRIMES_BOX_2_COUNT 73

static const uint32_t PRIMES_BOX_3[] = {
    547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631,
    641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733,
    739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
    839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
    947, 953, 967, 971, 977, 983, 991, 997
};
#define PRIMES_BOX_3_COUNT 68

static const uint32_t PRIMES_BOX_4[] = {
    1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
    1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
    1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249,
    1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321,
    1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
    1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
    1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601,
    1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693,
    1697, 1699, 1709, 1721
};
#define PRIMES_BOX_4_COUNT 100

static const uint32_t PRIMES_BOX_5[] = {
    1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811,
    1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907,
    1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003,
    2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089,
    2099, 2111
};
#define PRIMES_BOX_5_COUNT 50

static const uint32_t PRIMES_BOX_6[] = {
    2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617,
    2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693,
    2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777,
    2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861,
    2879, 2887
};
#define PRIMES_BOX_6_COUNT 50

/* ConfiguraÃ§Ãµes por nÃ­vel */
static const tav_config_t CONFIGS[] = {
    {0}, /* Placeholder for index 0 */
    /* IOT (1) */
    {32, 16, 12, 8, 2, 2, 2, {1, 2, 0, 0, 0, 0}, 2},
    /* CONSUMER (2) */
    {48, 24, 16, 12, 2, 3, 3, {1, 2, 3, 0, 0, 0}, 3},
    /* ENTERPRISE (3) */
    {64, 32, 16, 16, 3, 4, 4, {1, 2, 3, 4, 0, 0}, 4},
    /* MILITARY (4) */
    {64, 32, 24, 24, 4, 6, 6, {1, 2, 3, 4, 5, 6}, 6}
};

/* ConfiguraÃ§Ã£o dos relÃ³gios */
static const uint8_t CLOCK_PRIMES[] = {17, 23, 31, 47};
static const uint8_t CLOCK_BOXES[][3] = {
    {1, 2, 3}, {1, 3, 4}, {2, 3, 4}, {2, 4, 5}
};

/* ============================================================================
 * FUNÃ‡Ã•ES AUXILIARES
 * ============================================================================ */

uint64_t tav_get_time_ns(void) {
#ifdef _WIN32
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((counter.QuadPart * 1000000000ULL) / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

bool tav_constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

/* ============================================================================
 * MIXER FEISTEL
 * ============================================================================ */

static void mixer_mix(uint8_t* pool, size_t len, uint8_t n_rounds) {
    for (uint8_t round = 0; round < n_rounds; round++) {
        for (size_t i = 0; i < len; i++) {
            uint8_t x = pool[i];
            x = tav_rot_left(x, (round + i) & 7);
            x = x & TAV_CONST_AND[(i + round * 7) & 31];
            x = x | TAV_CONST_OR[(i + round * 11) & 31];
            x = x ^ pool[(i + round + 1) % len];
            pool[i] = x;
        }
    }
}

static void mixer_update(tav_mixer_t* mixer, uint64_t entropy) {
    size_t pos = mixer->counter % TAV_POOL_SIZE;
    for (int i = 0; i < 8; i++) {
        mixer->pool[(pos + i) % TAV_POOL_SIZE] ^= (entropy >> (i * 8)) & 0xFF;
    }
    mixer->counter++;
    mixer_mix(mixer->pool, TAV_POOL_SIZE, mixer->n_rounds);
}

static void mixer_extract(tav_mixer_t* mixer, uint8_t* out, size_t len) {
    mixer_mix(mixer->pool, TAV_POOL_SIZE, mixer->n_rounds);
    for (size_t i = 0; i < len; i++) {
        out[i] = mixer->pool[i % TAV_POOL_SIZE];
    }
    for (size_t i = 0; i < TAV_POOL_SIZE; i++) {
        mixer->pool[i] ^= 0x55;
    }
    mixer_mix(mixer->pool, TAV_POOL_SIZE, mixer->n_rounds);
}

/* ============================================================================
 * MAC FEISTEL
 * ============================================================================ */

static void mac_calculate(const uint8_t* key, size_t key_len,
                         const uint8_t* data, size_t data_len,
                         uint8_t n_rounds, uint8_t* out, size_t out_len) {
    uint8_t state[32];
    for (size_t i = 0; i < 32; i++) {
        state[i] = key[i % key_len];
    }
    for (size_t i = 0; i < data_len; i++) {
        state[i % 32] ^= data[i];
        if ((i + 1) % 32 == 0) {
            mixer_mix(state, 32, n_rounds);
        }
    }
    for (uint8_t r = 0; r < n_rounds; r++) {
        mixer_mix(state, 32, 1);
    }
    memcpy(out, state, out_len);
}

static bool mac_verify(const uint8_t* key, size_t key_len,
                      const uint8_t* data, size_t data_len,
                      uint8_t n_rounds,
                      const uint8_t* expected_mac, size_t mac_len) {
    uint8_t calculated[TAV_MAX_MAC_BYTES];
    mac_calculate(key, key_len, data, data_len, n_rounds, calculated, mac_len);
    return tav_constant_time_compare(calculated, expected_mac, mac_len);
}

/* ============================================================================
 * GERADOR DE ENTROPIA
 * ============================================================================ */

static uint64_t entropy_collect(tav_entropy_t* ent) {
    static volatile int work_result;
    uint64_t t1 = tav_get_time_ns();
    switch (ent->work_index & 3) {
        case 0: for (int i = 0; i < 10; i++) work_result += i; break;
        case 1: for (int i = 0; i < 8; i++) work_result += i; break;
        case 2: for (int i = 0; i < 12; i++) work_result += i; break;
        case 3: for (int i = 0; i < 5; i++) work_result += i * i; break;
    }
    ent->work_index++;
    uint64_t t2 = tav_get_time_ns();
    return t2 - t1;
}

static uint64_t entropy_collect_xor(tav_entropy_t* ent) {
    uint64_t result = 0;
    for (uint8_t i = 0; i < ent->n_xor; i++) {
        result ^= entropy_collect(ent);
    }
    return result;
}

static void entropy_generate(tav_entropy_t* ent, uint8_t* out, size_t len) {
    /* Limpa pool antigo */
    for (int i = 0; i < 4; i++) {
        if (ent->hot_pool[i].size > 0 && 
            ent->current_tx - ent->hot_pool[i].tx_created > TAV_POOL_TTL) {
            ent->hot_pool[i].size = 0;
        }
    }
    
    size_t offset = 0;
    /* Tenta usar pool quente */
    for (int i = 0; i < 4 && offset < len; i++) {
        if (ent->hot_pool[i].size > 0) {
            size_t to_copy = (ent->hot_pool[i].size < len - offset) ? 
                              ent->hot_pool[i].size : (len - offset);
            memcpy(out + offset, ent->hot_pool[i].data, to_copy);
            offset += to_copy;
            ent->hot_pool[i].size = 0;
        }
    }
    
    /* Gera mais se necessÃ¡rio */
    while (offset < len) {
        uint64_t timing = entropy_collect_xor(ent);
        mixer_update(&ent->mixer, timing);
        size_t chunk = (len - offset < TAV_POOL_SIZE) ? (len - offset) : TAV_POOL_SIZE;
        mixer_extract(&ent->mixer, out + offset, chunk);
        offset += chunk;
    }
}

static void entropy_generate_nonce(tav_entropy_t* ent, uint8_t* nonce, size_t len) {
    ent->nonce_counter++;
    uint64_t t1 = entropy_collect_xor(ent);
    uint64_t t2 = entropy_collect_xor(ent);
    
    memset(nonce, 0, len);
    for (size_t i = 0; i < 8 && i < len; i++) {
        nonce[i] = (t1 >> (i * 8)) & 0xFF;
    }
    uint32_t counter = (uint32_t)ent->nonce_counter;
    for (size_t i = 0; i < 4 && i + 8 < len; i++) {
        nonce[8 + i] = (counter >> ((3 - i) * 8)) & 0xFF;
    }
    for (size_t i = 0; i < 4 && i + 12 < len; i++) {
        nonce[12 + i] = (t2 >> (i * 8)) & 0xFF;
    }
}

/* ============================================================================
 * CAIXAS DE PRIMOS E RELÃ“GIOS
 * ============================================================================ */

static void init_prime_boxes(tav_prime_box_t boxes[TAV_MAX_BOXES]) {
    boxes[0].primes = PRIMES_BOX_1; boxes[0].count = PRIMES_BOX_1_COUNT;
    boxes[1].primes = PRIMES_BOX_2; boxes[1].count = PRIMES_BOX_2_COUNT;
    boxes[2].primes = PRIMES_BOX_3; boxes[2].count = PRIMES_BOX_3_COUNT;
    boxes[3].primes = PRIMES_BOX_4; boxes[3].count = PRIMES_BOX_4_COUNT;
    boxes[4].primes = PRIMES_BOX_5; boxes[4].count = PRIMES_BOX_5_COUNT;
    boxes[5].primes = PRIMES_BOX_6; boxes[5].count = PRIMES_BOX_6_COUNT;
    for (int i = 0; i < TAV_MAX_BOXES; i++) {
        boxes[i].index = 0;
        boxes[i].active = false;
    }
}

static void box_advance(tav_prime_box_t* box) {
    if (box->active && box->count > 0) {
        box->index = (box->index + 1) % box->count;
    }
}

static uint32_t box_current_prime(const tav_prime_box_t* box) {
    if (!box->active || box->count == 0) return 1;
    return box->primes[box->index];
}

static void init_clocks(tav_clock_t clocks[TAV_MAX_CLOCKS], tav_level_t level) {
    for (int i = 0; i < TAV_MAX_CLOCKS; i++) {
        clocks[i].tick_prime = CLOCK_PRIMES[i];
        memcpy(clocks[i].boxes, CLOCK_BOXES[i], 3);
        clocks[i].n_boxes = 3;
        clocks[i].tick_count = 0;
        clocks[i].tx_count = 0;
        clocks[i].active = (i < (int)level);
    }
}

static bool clock_tick(tav_clock_t* clock) {
    if (!clock->active) return false;
    clock->tx_count++;
    if (clock->tx_count >= clock->tick_prime) {
        clock->tick_count++;
        clock->tx_count = clock->tx_count % clock->tick_prime;
        return true;
    }
    return false;
}

/* ============================================================================
 * DERIVAÃ‡ÃƒO DE CHAVE
 * ============================================================================ */

static void derive_key(tav_ctx_t* ctx, uint8_t* key) {
    uint32_t state_sum = 0;
    for (int c = 0; c < TAV_MAX_CLOCKS; c++) {
        if (ctx->clocks[c].active) {
            state_sum += ctx->clocks[c].tick_count * 1000 + ctx->clocks[c].tx_count;
        }
    }
    
    size_t key_len = ctx->config.key_bytes;
    size_t offset = (state_sum * 7) % (ctx->master_entropy_size > key_len ? 
                                        ctx->master_entropy_size - key_len : 1);
    
    memcpy(key, ctx->master_entropy + offset, key_len);
    
    /* XOR com primos ativos */
    for (int c = 0; c < TAV_MAX_CLOCKS; c++) {
        if (!ctx->clocks[c].active) continue;
        for (int b = 0; b < ctx->clocks[c].n_boxes; b++) {
            int box_idx = ctx->clocks[c].boxes[b] - 1;
            if (box_idx >= 0 && box_idx < TAV_MAX_BOXES && ctx->boxes[box_idx].active) {
                uint32_t prime = box_current_prime(&ctx->boxes[box_idx]);
                for (int j = 0; j < 4; j++) {
                    size_t pos = (c * 4 + j) % key_len;
                    key[pos] ^= (prime >> (j * 8)) & 0xFF;
                }
            }
        }
    }
}

static void derive_checkpoint_key(const uint8_t* seed, size_t seed_len, uint8_t* key) {
    /* Deriva chave fixa de 32 bytes para checkpoint */
    const char* suffix = "_TAV_CHECKPOINT_KEY_V93";
    size_t suffix_len = strlen(suffix);
    
    memset(key, 0, 32);
    for (size_t i = 0; i < seed_len; i++) {
        key[i % 32] ^= seed[i];
    }
    for (size_t i = 0; i < suffix_len; i++) {
        key[(seed_len + i) % 32] ^= (uint8_t)suffix[i];
    }
    
    /* Mixer simples */
    for (int round = 0; round < 4; round++) {
        for (int i = 0; i < 32; i++) {
            key[i] = tav_rot_left(key[i], (round + i) & 7) ^ key[(i + 1) % 32];
        }
    }
}

/* ============================================================================
 * KEYSTREAM
 * ============================================================================ */

static void generate_keystream(const uint8_t* key, size_t key_len,
                               const uint8_t* nonce, size_t nonce_len,
                               uint8_t* keystream, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t k = key[i % key_len];
        uint8_t n = nonce[i % nonce_len];
        keystream[i] = tav_rot_left(k, i & 7) ^ n ^ (i & 0xFF);
    }
}

/* ============================================================================
 * CHECKPOINT
 * ============================================================================ */

static void serialize_checkpoint(tav_ctx_t* ctx, uint8_t* data, size_t* len) {
    size_t pos = 0;
    
    /* VersÃ£o "TAV93" */
    data[pos++] = 'T'; data[pos++] = 'A'; data[pos++] = 'V';
    data[pos++] = '9'; data[pos++] = '3';
    
    /* tx_count_global (8 bytes) */
    for (int i = 7; i >= 0; i--) data[pos++] = (ctx->tx_count_global >> (i * 8)) & 0xFF;
    
    /* boot_count (4 bytes) */
    for (int i = 3; i >= 0; i--) data[pos++] = (ctx->boot_count >> (i * 8)) & 0xFF;
    
    /* level (1 byte) */
    data[pos++] = (uint8_t)ctx->level;
    
    /* master_entropy_size (1 byte) + master_entropy */
    data[pos++] = ctx->master_entropy_size;
    memcpy(data + pos, ctx->master_entropy, ctx->master_entropy_size);
    pos += ctx->master_entropy_size;
    
    /* Clocks */
    for (int c = 0; c < TAV_MAX_CLOCKS; c++) {
        for (int i = 3; i >= 0; i--) data[pos++] = (ctx->clocks[c].tick_count >> (i * 8)) & 0xFF;
        for (int i = 3; i >= 0; i--) data[pos++] = (ctx->clocks[c].tx_count >> (i * 8)) & 0xFF;
    }
    
    /* Boxes */
    for (int b = 0; b < TAV_MAX_BOXES; b++) {
        data[pos++] = (ctx->boxes[b].index >> 8) & 0xFF;
        data[pos++] = ctx->boxes[b].index & 0xFF;
    }
    
    /* Hardware profile (40 bytes - 8 floats + 2 floats) */
    for (int i = 0; i < 8; i++) {
        uint32_t f;
        memcpy(&f, &ctx->baseline.bias_bits[i], sizeof(float));
        for (int j = 3; j >= 0; j--) data[pos++] = (f >> (j * 8)) & 0xFF;
    }
    {
        uint32_t f;
        memcpy(&f, &ctx->baseline.timing_mean, sizeof(float));
        for (int j = 3; j >= 0; j--) data[pos++] = (f >> (j * 8)) & 0xFF;
        memcpy(&f, &ctx->baseline.timing_std, sizeof(float));
        for (int j = 3; j >= 0; j--) data[pos++] = (f >> (j * 8)) & 0xFF;
    }
    
    /* nonce_counter (8 bytes) */
    for (int i = 7; i >= 0; i--) data[pos++] = (ctx->entropy.nonce_counter >> (i * 8)) & 0xFF;
    
    *len = pos;
}

static bool deserialize_checkpoint(tav_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (len < 5 || memcmp(data, "TAV93", 5) != 0) return false;
    
    size_t pos = 5;
    
    /* tx_count_global */
    ctx->tx_count_global = 0;
    for (int i = 0; i < 8; i++) ctx->tx_count_global = (ctx->tx_count_global << 8) | data[pos++];
    
    /* boot_count */
    ctx->boot_count = 0;
    for (int i = 0; i < 4; i++) ctx->boot_count = (ctx->boot_count << 8) | data[pos++];
    
    /* level (skip - use current) */
    pos++;
    
    /* master_entropy */
    uint8_t me_size = data[pos++];
    if (me_size <= TAV_MAX_MASTER_ENTROPY) {
        memcpy(ctx->master_entropy, data + pos, me_size);
        ctx->master_entropy_size = me_size;
    }
    pos += me_size;
    
    /* Clocks */
    for (int c = 0; c < TAV_MAX_CLOCKS; c++) {
        ctx->clocks[c].tick_count = 0;
        for (int i = 0; i < 4; i++) ctx->clocks[c].tick_count = (ctx->clocks[c].tick_count << 8) | data[pos++];
        ctx->clocks[c].tx_count = 0;
        for (int i = 0; i < 4; i++) ctx->clocks[c].tx_count = (ctx->clocks[c].tx_count << 8) | data[pos++];
    }
    
    /* Boxes */
    for (int b = 0; b < TAV_MAX_BOXES; b++) {
        ctx->boxes[b].index = (data[pos] << 8) | data[pos + 1];
        pos += 2;
    }
    
    /* Hardware profile saved */
    tav_hw_profile_t saved_profile;
    for (int i = 0; i < 8; i++) {
        uint32_t f = 0;
        for (int j = 0; j < 4; j++) f = (f << 8) | data[pos++];
        memcpy(&saved_profile.bias_bits[i], &f, sizeof(float));
    }
    {
        uint32_t f = 0;
        for (int j = 0; j < 4; j++) f = (f << 8) | data[pos++];
        memcpy(&saved_profile.timing_mean, &f, sizeof(float));
        f = 0;
        for (int j = 0; j < 4; j++) f = (f << 8) | data[pos++];
        memcpy(&saved_profile.timing_std, &f, sizeof(float));
    }
    
    /* Compare hardware profiles */
    float sim = 1.0f;
    if (ctx->baseline.timing_mean > 0) {
        float diff_bias = 0;
        for (int i = 0; i < 8; i++) {
            float d = ctx->baseline.bias_bits[i] - saved_profile.bias_bits[i];
            diff_bias += (d < 0 ? -d : d);
        }
        sim = 1.0f - (diff_bias / 8.0f);
    }
    ctx->hardware_changed = (sim < 0.7f);
    
    /* nonce_counter */
    ctx->entropy.nonce_counter = 0;
    for (int i = 0; i < 8; i++) ctx->entropy.nonce_counter = (ctx->entropy.nonce_counter << 8) | data[pos++];
    
    return true;
}

static tav_result_t checkpoint_encrypt_internal(tav_ctx_t* ctx, 
                                                 const uint8_t* plain, size_t plain_len,
                                                 uint8_t* cipher, size_t* cipher_len) {
    /* Usa checkpoint_key, nonce de 16 bytes, mac de 16 bytes */
    uint8_t nonce[16], mac[16];
    entropy_generate_nonce(&ctx->entropy, nonce, 16);
    
    /* Cifra */
    uint8_t keystream[512];
    generate_keystream(ctx->checkpoint_key, 32, nonce, 16, keystream, plain_len);
    
    uint8_t* encrypted = cipher + 16 + 16;
    for (size_t i = 0; i < plain_len; i++) {
        encrypted[i] = plain[i] ^ keystream[i];
    }
    
    /* MAC */
    uint8_t mac_input[16 + 512];
    memcpy(mac_input, nonce, 16);
    memcpy(mac_input + 16, encrypted, plain_len);
    mac_calculate(ctx->checkpoint_key, 32, mac_input, 16 + plain_len, 4, mac, 16);
    
    /* Monta: nonce + mac + encrypted */
    memcpy(cipher, nonce, 16);
    memcpy(cipher + 16, mac, 16);
    *cipher_len = 16 + 16 + plain_len;
    
    return TAV_OK;
}

static tav_result_t checkpoint_decrypt_internal(tav_ctx_t* ctx,
                                                 const uint8_t* cipher, size_t cipher_len,
                                                 uint8_t* plain, size_t* plain_len) {
    if (cipher_len < 32) return TAV_ERROR_INVALID_DATA;
    
    const uint8_t* nonce = cipher;
    const uint8_t* mac_received = cipher + 16;
    const uint8_t* encrypted = cipher + 32;
    size_t encrypted_len = cipher_len - 32;
    
    /* Verifica MAC */
    uint8_t mac_input[16 + 512];
    memcpy(mac_input, nonce, 16);
    memcpy(mac_input + 16, encrypted, encrypted_len);
    
    if (!mac_verify(ctx->checkpoint_key, 32, mac_input, 16 + encrypted_len, 4, mac_received, 16)) {
        return TAV_ERROR_MAC_MISMATCH;
    }
    
    /* Decifra */
    uint8_t keystream[512];
    generate_keystream(ctx->checkpoint_key, 32, nonce, 16, keystream, encrypted_len);
    
    for (size_t i = 0; i < encrypted_len; i++) {
        plain[i] = encrypted[i] ^ keystream[i];
    }
    *plain_len = encrypted_len;
    
    return TAV_OK;
}

/* ============================================================================
 * API PRINCIPAL
 * ============================================================================ */

void tav_set_checkpoint_callbacks(tav_ctx_t* ctx,
    int (*save)(const uint8_t* data, size_t len, void* user_data),
    int (*load)(uint8_t* data, size_t* len, void* user_data),
    void* user_data) {
    if (ctx) {
        ctx->checkpoint_save = save;
        ctx->checkpoint_load = load;
        ctx->checkpoint_user_data = user_data;
    }
}

static void try_load_checkpoint(tav_ctx_t* ctx) {
    if (!ctx->checkpoint_load) {
        ctx->boot_count = 1;
        return;
    }
    
    uint8_t encrypted[512];
    size_t encrypted_len = sizeof(encrypted);
    
    if (ctx->checkpoint_load(encrypted, &encrypted_len, ctx->checkpoint_user_data) != 0) {
        ctx->boot_count = 1;
        return;
    }
    
    uint8_t plain[512];
    size_t plain_len;
    
    if (checkpoint_decrypt_internal(ctx, encrypted, encrypted_len, plain, &plain_len) != TAV_OK) {
        ctx->boot_count = 1;
        return;
    }
    
    if (deserialize_checkpoint(ctx, plain, plain_len)) {
        ctx->boot_count++;
        ctx->last_checkpoint_tx = ctx->tx_count_global;
    } else {
        ctx->boot_count = 1;
    }
}

static void try_save_checkpoint(tav_ctx_t* ctx) {
    if (!ctx->checkpoint_save) return;
    
    uint8_t plain[512];
    size_t plain_len;
    serialize_checkpoint(ctx, plain, &plain_len);
    
    uint8_t encrypted[512];
    size_t encrypted_len;
    
    if (checkpoint_encrypt_internal(ctx, plain, plain_len, encrypted, &encrypted_len) == TAV_OK) {
        ctx->checkpoint_save(encrypted, encrypted_len, ctx->checkpoint_user_data);
        ctx->last_checkpoint_tx = ctx->tx_count_global;
    }
}

tav_result_t tav_init(tav_ctx_t* ctx, const uint8_t* seed, size_t seed_len, tav_level_t level) {
    if (!ctx || !seed) return TAV_ERROR_NULL_POINTER;
    if (level < TAV_LEVEL_IOT || level > TAV_LEVEL_MILITARY) return TAV_ERROR_INVALID_LEVEL;
    
    memset(ctx, 0, sizeof(tav_ctx_t));
    
    ctx->level = level;
    ctx->config = CONFIGS[level];
    
    /* Deriva chave de checkpoint (PRIMEIRO) */
    derive_checkpoint_key(seed, seed_len, ctx->checkpoint_key);
    
    /* Inicializa entropia */
    ctx->entropy.n_xor = ctx->config.n_xor;
    ctx->entropy.mixer.n_rounds = ctx->config.n_rounds_mixer;
    ctx->entropy.nonce_counter = 0;
    ctx->entropy.work_index = 0;
    ctx->entropy.hot_pool_count = 0;
    ctx->entropy.current_tx = 0;
    memset(ctx->entropy.mixer.pool, 0, TAV_POOL_SIZE);
    
    /* Calibra (prÃ©-aquece) */
    for (int i = 0; i < 100; i++) {
        uint64_t timing = entropy_collect_xor(&ctx->entropy);
        mixer_update(&ctx->entropy.mixer, timing);
    }
    
    /* Captura perfil de hardware */
    uint64_t samples[100];
    for (int i = 0; i < 100; i++) {
        samples[i] = entropy_collect_xor(&ctx->entropy);
    }
    for (int bit = 0; bit < 8; bit++) {
        int count = 0;
        for (int i = 0; i < 100; i++) {
            if ((samples[i] >> bit) & 1) count++;
        }
        ctx->baseline.bias_bits[bit] = (float)count / 100.0f;
    }
    float sum = 0, sum_sq = 0;
    for (int i = 0; i < 100; i++) {
        sum += (float)samples[i];
        sum_sq += (float)samples[i] * (float)samples[i];
    }
    ctx->baseline.timing_mean = sum / 100.0f;
    float variance = (sum_sq / 100.0f) - (ctx->baseline.timing_mean * ctx->baseline.timing_mean);
    ctx->baseline.timing_std = (variance > 0) ? sqrtf(variance) : 0;
    
    /* Inicializa MAC */
    ctx->mac.n_rounds = ctx->config.n_rounds_mac;
    
    /* Inicializa caixas */
    init_prime_boxes(ctx->boxes);
    for (int i = 0; i < ctx->config.n_initial_boxes; i++) {
        int box_idx = ctx->config.initial_boxes[i] - 1;
        if (box_idx >= 0 && box_idx < TAV_MAX_BOXES) {
            ctx->boxes[box_idx].active = true;
        }
    }
    
    /* Inicializa relÃ³gios */
    init_clocks(ctx->clocks, level);
    
    /* Gera master entropy */
    ctx->master_entropy_size = ctx->config.master_entropy_size;
    
    uint8_t seed_normalized[TAV_MAX_MASTER_ENTROPY];
    memset(seed_normalized, 0, ctx->master_entropy_size);
    for (size_t i = 0; i < seed_len; i++) {
        seed_normalized[i % ctx->master_entropy_size] ^= seed[i];
    }
    
    uint8_t clock_entropy[TAV_MAX_MASTER_ENTROPY * 2];
    entropy_generate(&ctx->entropy, clock_entropy, ctx->master_entropy_size * 2);
    
    for (size_t i = 0; i < ctx->master_entropy_size; i++) {
        ctx->master_entropy[i] = seed_normalized[i] ^ clock_entropy[i];
    }
    for (size_t i = ctx->master_entropy_size; i < ctx->master_entropy_size * 2 && 
         i < TAV_MAX_MASTER_ENTROPY; i++) {
        ctx->master_entropy[i] = clock_entropy[i];
    }
    
    ctx->tx_count_global = 0;
    ctx->last_tx = 0;
    ctx->last_checkpoint_tx = 0;
    ctx->boot_count = 0;
    ctx->hardware_changed = false;
    ctx->initialized = true;
    
    /* Tenta carregar checkpoint */
    try_load_checkpoint(ctx);
    
    return TAV_OK;
}

void tav_cleanup(tav_ctx_t* ctx) {
    if (ctx) {
        memset(ctx->master_entropy, 0, sizeof(ctx->master_entropy));
        memset(ctx->checkpoint_key, 0, sizeof(ctx->checkpoint_key));
        memset(ctx->entropy.mixer.pool, 0, TAV_POOL_SIZE);
        ctx->initialized = false;
    }
}

size_t tav_overhead(tav_level_t level) {
    if (level < TAV_LEVEL_IOT || level > TAV_LEVEL_MILITARY) return 0;
    const tav_config_t* cfg = &CONFIGS[level];
    return cfg->nonce_bytes + cfg->mac_bytes + 8;
}

void tav_tick(tav_ctx_t* ctx, uint32_t n) {
    if (!ctx || !ctx->initialized) return;
    
    ctx->tx_count_global += n;
    ctx->last_tx = ctx->tx_count_global;
    ctx->entropy.current_tx = ctx->tx_count_global;
    
    for (uint32_t t = 0; t < n; t++) {
        for (int c = 0; c < TAV_MAX_CLOCKS; c++) {
            if (clock_tick(&ctx->clocks[c])) {
                for (int b = 0; b < ctx->clocks[c].n_boxes; b++) {
                    int box_idx = ctx->clocks[c].boxes[b] - 1;
                    if (box_idx >= 0 && box_idx < TAV_MAX_BOXES) {
                        box_advance(&ctx->boxes[box_idx]);
                    }
                }
            }
        }
    }
    
    /* RelÃ³gios lentos */
    if (ctx->tx_count_global % 100 == 0 && ctx->boxes[4].active) {
        box_advance(&ctx->boxes[4]);
    }
    if (ctx->tx_count_global % 1000 == 0 && ctx->boxes[5].active) {
        box_advance(&ctx->boxes[5]);
    }
    
    /* Checkpoint automÃ¡tico */
    if (ctx->tx_count_global - ctx->last_checkpoint_tx >= TAV_CHECKPOINT_INTERVAL) {
        try_save_checkpoint(ctx);
    }
}

tav_result_t tav_encrypt(tav_ctx_t* ctx,
                         const uint8_t* plaintext, size_t pt_len,
                         uint8_t* ciphertext, size_t* ct_len,
                         bool auto_tick) {
    if (!ctx || !ciphertext || !ct_len) return TAV_ERROR_NULL_POINTER;
    if (!ctx->initialized) return TAV_ERROR_NOT_INITIALIZED;
    
    size_t nonce_len = ctx->config.nonce_bytes;
    size_t mac_len = ctx->config.mac_bytes;
    size_t key_len = ctx->config.key_bytes;
    size_t metadata_len = 8;
    
    *ct_len = nonce_len + mac_len + metadata_len + pt_len;
    
    uint8_t key[TAV_MAX_KEY_BYTES];
    derive_key(ctx, key);
    
    uint8_t nonce[TAV_MAX_NONCE_BYTES];
    entropy_generate_nonce(&ctx->entropy, nonce, nonce_len);
    
    /* Metadata */
    uint8_t metadata[8];
    metadata[0] = TAV_VERSION_BYTE;
    metadata[1] = ctx->level;
    for (int i = 0; i < 6; i++) {
        metadata[2 + i] = (ctx->tx_count_global >> (40 - i * 8)) & 0xFF;
    }
    
    /* Cifra */
    uint8_t* encrypted = ciphertext + nonce_len + mac_len;
    uint8_t keystream[8];
    generate_keystream(key, key_len, nonce, nonce_len, keystream, 8);
    for (size_t i = 0; i < 8; i++) {
        encrypted[i] = metadata[i] ^ keystream[i];
    }
    
    if (pt_len > 0 && plaintext) {
        uint8_t* ks = (uint8_t*)malloc(pt_len);
        if (!ks) return TAV_ERROR_NULL_POINTER;
        generate_keystream(key, key_len, nonce, nonce_len, ks, pt_len);
        for (size_t i = 0; i < pt_len; i++) {
            encrypted[8 + i] = plaintext[i] ^ ks[i];
        }
        free(ks);
    }
    
    /* MAC */
    size_t total_enc = metadata_len + pt_len;
    uint8_t* mac_input = (uint8_t*)malloc(nonce_len + total_enc);
    if (!mac_input) return TAV_ERROR_NULL_POINTER;
    memcpy(mac_input, nonce, nonce_len);
    memcpy(mac_input + nonce_len, encrypted, total_enc);
    
    uint8_t mac[TAV_MAX_MAC_BYTES];
    mac_calculate(key, key_len, mac_input, nonce_len + total_enc, 
                  ctx->mac.n_rounds, mac, mac_len);
    free(mac_input);
    
    /* Monta */
    memcpy(ciphertext, nonce, nonce_len);
    memcpy(ciphertext + nonce_len, mac, mac_len);
    
    if (auto_tick) {
        tav_tick(ctx, 1);
    }
    
    return TAV_OK;
}

tav_result_t tav_decrypt(tav_ctx_t* ctx,
                         const uint8_t* ciphertext, size_t ct_len,
                         uint8_t* plaintext, size_t* pt_len) {
    if (!ctx || !ciphertext || !plaintext || !pt_len) return TAV_ERROR_NULL_POINTER;
    if (!ctx->initialized) return TAV_ERROR_NOT_INITIALIZED;
    
    size_t nonce_len = ctx->config.nonce_bytes;
    size_t mac_len = ctx->config.mac_bytes;
    size_t key_len = ctx->config.key_bytes;
    size_t overhead = nonce_len + mac_len + 8;
    
    if (ct_len < overhead) return TAV_ERROR_INVALID_DATA;
    
    const uint8_t* nonce = ciphertext;
    const uint8_t* mac_received = ciphertext + nonce_len;
    const uint8_t* encrypted = ciphertext + nonce_len + mac_len;
    size_t encrypted_len = ct_len - nonce_len - mac_len;
    
    uint8_t key[TAV_MAX_KEY_BYTES];
    derive_key(ctx, key);
    
    /* Verifica MAC */
    uint8_t* mac_input = (uint8_t*)malloc(nonce_len + encrypted_len);
    if (!mac_input) return TAV_ERROR_NULL_POINTER;
    memcpy(mac_input, nonce, nonce_len);
    memcpy(mac_input + nonce_len, encrypted, encrypted_len);
    
    uint8_t mac_expected[TAV_MAX_MAC_BYTES];
    mac_calculate(key, key_len, mac_input, nonce_len + encrypted_len,
                  ctx->mac.n_rounds, mac_expected, mac_len);
    free(mac_input);
    
    if (!tav_constant_time_compare(mac_received, mac_expected, mac_len)) {
        return TAV_ERROR_MAC_MISMATCH;
    }
    
    /* Decifra */
    uint8_t* ks = (uint8_t*)malloc(encrypted_len);
    if (!ks) return TAV_ERROR_NULL_POINTER;
    generate_keystream(key, key_len, nonce, nonce_len, ks, encrypted_len);
    
    for (size_t i = 0; i < encrypted_len; i++) {
        plaintext[i] = encrypted[i] ^ ks[i];
    }
    free(ks);
    
    *pt_len = encrypted_len - 8;
    memmove(plaintext, plaintext + 8, *pt_len);
    
    return TAV_OK;
}

bool tav_verify_hardware(tav_ctx_t* ctx, float* similarity) {
    if (!ctx || !ctx->initialized) {
        if (similarity) *similarity = 0.0f;
        return false;
    }
    
    uint64_t samples[100];
    for (int i = 0; i < 100; i++) {
        samples[i] = entropy_collect_xor(&ctx->entropy);
    }
    
    float bias_bits[8];
    for (int bit = 0; bit < 8; bit++) {
        int count = 0;
        for (int i = 0; i < 100; i++) {
            if ((samples[i] >> bit) & 1) count++;
        }
        bias_bits[bit] = (float)count / 100.0f;
    }
    
    float diff_bias = 0;
    for (int i = 0; i < 8; i++) {
        float d = ctx->baseline.bias_bits[i] - bias_bits[i];
        diff_bias += (d < 0 ? -d : d);
    }
    float sim = 1.0f - (diff_bias / 8.0f);
    
    if (similarity) *similarity = sim;
    return sim > 0.7f;
}

tav_result_t tav_force_checkpoint(tav_ctx_t* ctx) {
    if (!ctx || !ctx->initialized) return TAV_ERROR_NOT_INITIALIZED;
    try_save_checkpoint(ctx);
    return TAV_OK;
}

void tav_get_stats(tav_ctx_t* ctx, uint64_t* tx_count, uint32_t* boot_count,
                   uint64_t* last_checkpoint_tx, bool* hw_changed) {
    if (!ctx) return;
    if (tx_count) *tx_count = ctx->tx_count_global;
    if (boot_count) *boot_count = ctx->boot_count;
    if (last_checkpoint_tx) *last_checkpoint_tx = ctx->last_checkpoint_tx;
    if (hw_changed) *hw_changed = ctx->hardware_changed;
}
