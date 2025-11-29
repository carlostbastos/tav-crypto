"""
TAV Clock Cryptography v0.9
Copyright (C) 2025 Carlos Alberto Terencio de Bastos
License: AGPL-3.0 - https://github.com/carlostbastos/tav-crypto

TAV CLOCK CRYPTOGRAPHY V9.3 - COM CHECKPOINT AUTOMATICO
=========================================================

Novidades sobre V9.2:
1. Checkpoint automatico a cada 10.000 transacoes
2. Checkpoint hardcoded (caminho fixo, oculto do usuario)
3. Checkpoint criptografado pelo proprio TAV
4. Restauracao automatica na inicializacao
5. Deteccao de hardware diferente (aviso, nao bloqueio)

Operacoes: apenas XOR, AND, OR, ROT (portas logicas)
ZERO dependencia de algoritmos matematicos!

Prime Boxes:
- Box 1: 21 primes (2 digits: 11-97)
- Box 2: 143 primes (3 digits: 101-997)
- Box 3: 500 primes (4 digits: 1009-4993)
- Box 4: 500 primes (5 digits: 10007-14759)
- Box 5: 200 primes (7 digits: 1000003-1002583)
- Box 6: 100 primes (9 digits: 100000007-100001819)
- TOTAL: 1,464 primes

Licenca: AGPL-3.0 | Uso comercial gratuito ate maio de 2027
Data: Novembro 2025
Autor: Carlos Alberto Terencio de Bastos
"""

import os
import sys
import time
import struct
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


# =============================================================================
# CONFIGURACAO DE CHECKPOINT (HARDCODED)
# =============================================================================

CHECKPOINT_INTERVAL = 10000  # Salvar a cada N transacoes
CHECKPOINT_VERSION = b'TAV93'  # Identificador do formato

def _get_checkpoint_dir() -> Path:
    """Retorna diretorio de checkpoint baseado no SO."""
    if sys.platform == 'win32':
        base = Path(os.environ.get('LOCALAPPDATA', os.path.expanduser('~')))
        return base / 'TAV' / '.state'
    elif sys.platform == 'darwin':
        return Path.home() / 'Library' / 'Application Support' / 'TAV' / '.state'
    else:  # Linux e outros Unix
        xdg_data = os.environ.get('XDG_DATA_HOME', os.path.expanduser('~/.local/share'))
        return Path(xdg_data) / 'tav' / '.state'

def _get_checkpoint_path(instance_id: str = 'default') -> Path:
    """Retorna caminho completo do checkpoint."""
    return _get_checkpoint_dir() / f'.tav_{instance_id}.ckpt'


# =============================================================================
# CONSTANTES DO MIXER FEISTEL
# =============================================================================

CONST_AND = bytes([
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
    0xF7, 0xFB, 0xFD, 0xFE, 0x7F, 0xBF, 0xDF, 0xEF,
])

CONST_OR = bytes([
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
])


# =============================================================================
# NIVEIS DE SEGURANCA
# =============================================================================

class NivelSeguranca(IntEnum):
    IOT = 1
    CONSUMER = 2
    ENTERPRISE = 3
    MILITARY = 4

CONFIG_POR_NIVEL = {
    NivelSeguranca.IOT: {
        'n_xor': 2, 'n_rodadas_mixer': 2, 'n_rodadas_mac': 2,
        'chave_bits': 128, 'chave_bytes': 16, 'nonce_bytes': 12, 'mac_bytes': 8,
        'master_entropy': 32, 'pool_max': 64, 'pool_min': 32,
        'caixas_iniciais': {1, 2},
    },
    NivelSeguranca.CONSUMER: {
        'n_xor': 2, 'n_rodadas_mixer': 3, 'n_rodadas_mac': 3,
        'chave_bits': 192, 'chave_bytes': 24, 'nonce_bytes': 16, 'mac_bytes': 12,
        'master_entropy': 48, 'pool_max': 96, 'pool_min': 48,
        'caixas_iniciais': {1, 2, 3},
    },
    NivelSeguranca.ENTERPRISE: {
        'n_xor': 3, 'n_rodadas_mixer': 4, 'n_rodadas_mac': 4,
        'chave_bits': 256, 'chave_bytes': 32, 'nonce_bytes': 16, 'mac_bytes': 16,
        'master_entropy': 64, 'pool_max': 128, 'pool_min': 64,
        'caixas_iniciais': {1, 2, 3, 4},
    },
    NivelSeguranca.MILITARY: {
        'n_xor': 4, 'n_rodadas_mixer': 6, 'n_rodadas_mac': 6,
        'chave_bits': 256, 'chave_bytes': 32, 'nonce_bytes': 24, 'mac_bytes': 24,
        'master_entropy': 64, 'pool_max': 128, 'pool_min': 64,
        'caixas_iniciais': {1, 2, 3, 4, 5, 6},
    },
}

VERIFICACAO_POR_NIVEL = {
    NivelSeguranca.IOT: 20, NivelSeguranca.CONSUMER: 10,
    NivelSeguranca.ENTERPRISE: 5, NivelSeguranca.MILITARY: 1,
}

POOL_TTL = 1000


# =============================================================================
# PRIMOS HARDCODED POR CAIXA (1,464 primos total)
# =============================================================================

PRIMOS_POR_CAIXA = {
    # Box 1: 21 primes
    1: [
        11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
        59, 61, 67, 71, 73, 79, 83, 89, 97,
    ],
    # Box 2: 143 primes
    2: [
        101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
        163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
        229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
        293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367,
        373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439,
        443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,
        521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
        601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
        673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751,
        757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829,
        839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919,
        929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
    ],
    # Box 3: 500 primes
    3: [
        1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
        1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
        1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249,
        1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321,
        1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
        1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
        1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601,
        1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693,
        1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783,
        1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
        1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987,
        1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069,
        2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143,
        2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267,
        2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347,
        2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
        2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543,
        2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657,
        2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713,
        2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801,
        2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903,
        2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011,
        3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119,
        3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221,
        3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323,
        3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
        3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527,
        3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607,
        3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697,
        3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797,
        3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907,
        3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003,
        4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093,
        4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211,
        4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283,
        4289, 4297, 4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409,
        4421, 4423, 4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513,
        4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621,
        4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721,
        4723, 4729, 4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813,
        4817, 4831, 4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937,
        4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993,
    ],
    # Box 4: 500 primes
    4: [
        10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079, 10091, 10093, 10099, 10103,
        10111, 10133, 10139, 10141, 10151, 10159, 10163, 10169, 10177, 10181, 10193, 10211,
        10223, 10243, 10247, 10253, 10259, 10267, 10271, 10273, 10289, 10301, 10303, 10313,
        10321, 10331, 10333, 10337, 10343, 10357, 10369, 10391, 10399, 10427, 10429, 10433,
        10453, 10457, 10459, 10463, 10477, 10487, 10499, 10501, 10513, 10529, 10531, 10559,
        10567, 10589, 10597, 10601, 10607, 10613, 10627, 10631, 10639, 10651, 10657, 10663,
        10667, 10687, 10691, 10709, 10711, 10723, 10729, 10733, 10739, 10753, 10771, 10781,
        10789, 10799, 10831, 10837, 10847, 10853, 10859, 10861, 10867, 10883, 10889, 10891,
        10903, 10909, 10937, 10939, 10949, 10957, 10973, 10979, 10987, 10993, 11003, 11027,
        11047, 11057, 11059, 11069, 11071, 11083, 11087, 11093, 11113, 11117, 11119, 11131,
        11149, 11159, 11161, 11171, 11173, 11177, 11197, 11213, 11239, 11243, 11251, 11257,
        11261, 11273, 11279, 11287, 11299, 11311, 11317, 11321, 11329, 11351, 11353, 11369,
        11383, 11393, 11399, 11411, 11423, 11437, 11443, 11447, 11467, 11471, 11483, 11489,
        11491, 11497, 11503, 11519, 11527, 11549, 11551, 11579, 11587, 11593, 11597, 11617,
        11621, 11633, 11657, 11677, 11681, 11689, 11699, 11701, 11717, 11719, 11731, 11743,
        11777, 11779, 11783, 11789, 11801, 11807, 11813, 11821, 11827, 11831, 11833, 11839,
        11863, 11867, 11887, 11897, 11903, 11909, 11923, 11927, 11933, 11939, 11941, 11953,
        11959, 11969, 11971, 11981, 11987, 12007, 12011, 12037, 12041, 12043, 12049, 12071,
        12073, 12097, 12101, 12107, 12109, 12113, 12119, 12143, 12149, 12157, 12161, 12163,
        12197, 12203, 12211, 12227, 12239, 12241, 12251, 12253, 12263, 12269, 12277, 12281,
        12289, 12301, 12323, 12329, 12343, 12347, 12373, 12377, 12379, 12391, 12401, 12409,
        12413, 12421, 12433, 12437, 12451, 12457, 12473, 12479, 12487, 12491, 12497, 12503,
        12511, 12517, 12527, 12539, 12541, 12547, 12553, 12569, 12577, 12583, 12589, 12601,
        12611, 12613, 12619, 12637, 12641, 12647, 12653, 12659, 12671, 12689, 12697, 12703,
        12713, 12721, 12739, 12743, 12757, 12763, 12781, 12791, 12799, 12809, 12821, 12823,
        12829, 12841, 12853, 12889, 12893, 12899, 12907, 12911, 12917, 12919, 12923, 12941,
        12953, 12959, 12967, 12973, 12979, 12983, 13001, 13003, 13007, 13009, 13033, 13037,
        13043, 13049, 13063, 13093, 13099, 13103, 13109, 13121, 13127, 13147, 13151, 13159,
        13163, 13171, 13177, 13183, 13187, 13217, 13219, 13229, 13241, 13249, 13259, 13267,
        13291, 13297, 13309, 13313, 13327, 13331, 13337, 13339, 13367, 13381, 13397, 13399,
        13411, 13417, 13421, 13441, 13451, 13457, 13463, 13469, 13477, 13487, 13499, 13513,
        13523, 13537, 13553, 13567, 13577, 13591, 13597, 13613, 13619, 13627, 13633, 13649,
        13669, 13679, 13681, 13687, 13691, 13693, 13697, 13709, 13711, 13721, 13723, 13729,
        13751, 13757, 13759, 13763, 13781, 13789, 13799, 13807, 13829, 13831, 13841, 13859,
        13873, 13877, 13879, 13883, 13901, 13903, 13907, 13913, 13921, 13931, 13933, 13963,
        13967, 13997, 13999, 14009, 14011, 14029, 14033, 14051, 14057, 14071, 14081, 14083,
        14087, 14107, 14143, 14149, 14153, 14159, 14173, 14177, 14197, 14207, 14221, 14243,
        14249, 14251, 14281, 14293, 14303, 14321, 14323, 14327, 14341, 14347, 14369, 14387,
        14389, 14401, 14407, 14411, 14419, 14423, 14431, 14437, 14447, 14449, 14461, 14479,
        14489, 14503, 14519, 14533, 14537, 14543, 14549, 14551, 14557, 14561, 14563, 14591,
        14593, 14621, 14627, 14629, 14633, 14639, 14653, 14657, 14669, 14683, 14699, 14713,
        14717, 14723, 14731, 14737, 14741, 14747, 14753, 14759,
    ],
    # Box 5: 200 primes
    5: [
        1000003, 1000033, 1000037, 1000039, 1000081, 1000099, 1000117, 1000121, 1000133, 1000151, 1000159, 1000171,
        1000183, 1000187, 1000193, 1000199, 1000211, 1000213, 1000231, 1000249, 1000253, 1000273, 1000289, 1000291,
        1000303, 1000313, 1000333, 1000357, 1000367, 1000381, 1000393, 1000397, 1000403, 1000409, 1000423, 1000427,
        1000429, 1000453, 1000457, 1000507, 1000537, 1000541, 1000547, 1000577, 1000579, 1000589, 1000609, 1000619,
        1000621, 1000639, 1000651, 1000667, 1000669, 1000679, 1000691, 1000697, 1000721, 1000723, 1000763, 1000777,
        1000793, 1000829, 1000847, 1000849, 1000859, 1000861, 1000889, 1000907, 1000919, 1000921, 1000931, 1000969,
        1000973, 1000981, 1000999, 1001003, 1001017, 1001023, 1001027, 1001041, 1001069, 1001081, 1001087, 1001089,
        1001093, 1001107, 1001123, 1001153, 1001159, 1001173, 1001177, 1001191, 1001197, 1001219, 1001237, 1001267,
        1001279, 1001291, 1001303, 1001311, 1001321, 1001323, 1001327, 1001347, 1001353, 1001369, 1001381, 1001387,
        1001389, 1001401, 1001411, 1001431, 1001447, 1001459, 1001467, 1001491, 1001501, 1001527, 1001531, 1001549,
        1001551, 1001563, 1001569, 1001587, 1001593, 1001621, 1001629, 1001639, 1001659, 1001669, 1001683, 1001687,
        1001713, 1001723, 1001743, 1001783, 1001797, 1001801, 1001807, 1001809, 1001821, 1001831, 1001839, 1001911,
        1001933, 1001941, 1001947, 1001953, 1001977, 1001981, 1001983, 1001989, 1002017, 1002049, 1002061, 1002073,
        1002077, 1002083, 1002091, 1002101, 1002109, 1002121, 1002143, 1002149, 1002151, 1002173, 1002191, 1002227,
        1002241, 1002247, 1002257, 1002259, 1002263, 1002289, 1002299, 1002341, 1002343, 1002347, 1002349, 1002359,
        1002361, 1002377, 1002403, 1002427, 1002433, 1002451, 1002457, 1002467, 1002481, 1002487, 1002493, 1002503,
        1002511, 1002517, 1002523, 1002527, 1002553, 1002569, 1002577, 1002583,
    ],
    # Box 6: 100 primes
    6: [
        100000007, 100000037, 100000039, 100000049, 100000073, 100000081, 100000123, 100000127, 100000193, 100000213, 100000217, 100000223,
        100000231, 100000237, 100000259, 100000267, 100000279, 100000357, 100000379, 100000393, 100000399, 100000421, 100000429, 100000463,
        100000469, 100000471, 100000493, 100000541, 100000543, 100000561, 100000567, 100000577, 100000609, 100000627, 100000643, 100000651,
        100000661, 100000669, 100000673, 100000687, 100000717, 100000721, 100000793, 100000799, 100000801, 100000837, 100000841, 100000853,
        100000891, 100000921, 100000937, 100000939, 100000963, 100000969, 100001029, 100001053, 100001059, 100001081, 100001087, 100001107,
        100001119, 100001131, 100001147, 100001159, 100001177, 100001183, 100001203, 100001207, 100001219, 100001227, 100001303, 100001329,
        100001333, 100001347, 100001357, 100001399, 100001431, 100001449, 100001467, 100001507, 100001533, 100001537, 100001569, 100001581,
        100001591, 100001611, 100001623, 100001651, 100001653, 100001687, 100001689, 100001719, 100001761, 100001767, 100001777, 100001791,
        100001801, 100001809, 100001813, 100001819,
    ],
}

# Pre-compute primes as bytes for faster key derivation
PRIMOS_BYTES_POR_CAIXA = {
    caixa: [p.to_bytes(8, 'big') for p in primos]
    for caixa, primos in PRIMOS_POR_CAIXA.items()
}


RELOGIOS_CONFIG = [
    {'id': 0, 'tick_prime': 17, 'caixas': [1, 2, 3]},
    {'id': 1, 'tick_prime': 23, 'caixas': [1, 3, 4]},
    {'id': 2, 'tick_prime': 31, 'caixas': [2, 3, 4]},
    {'id': 3, 'tick_prime': 47, 'caixas': [2, 4, 5]},
]

# =============================================================================
# LOOKUP TABLES ROT_LEFT PRE-COMPUTADAS
# =============================================================================

def _gerar_rot_left():
    """Gera tabelas de rotacao."""
    tables = []
    for rot in range(8):
        table = bytearray(256)
        for b in range(256):
            table[b] = ((b << rot) | (b >> (8 - rot))) & 0xFF
        tables.append(bytes(table))
    return tuple(tables)

ROT_LEFT = _gerar_rot_left()


# =============================================================================
# MIXER FEISTEL
# =============================================================================

class MixerFeistel:
    def __init__(self, pool_size: int = 64, n_rodadas: int = 3):
        self.n_rodadas = n_rodadas
        self.pool = bytearray(pool_size)
        self.posicao = 0
    
    def atualizar(self, valor: int):
        valor_bytes = valor.to_bytes(8, 'big')
        for b in valor_bytes:
            self.pool[self.posicao] ^= b
            self.posicao = (self.posicao + 1) % len(self.pool)
        self._mix()
    
    def _mix(self):
        n = len(self.pool)
        for rodada in range(self.n_rodadas):
            for i in range(n):
                x = self.pool[i]
                rotacao = (rodada + i) & 7
                x = ROT_LEFT[rotacao][x]
                x = x & CONST_AND[(i + rodada * 7) & 31]
                x = x | CONST_OR[(i + rodada * 11) & 31]
                x = x ^ self.pool[(i + rodada + 1) % n]
                self.pool[i] = x
    
    def extrair(self, n_bytes: int) -> bytes:
        self._mix()
        resultado = bytes(self.pool[:n_bytes])
        for i in range(n_bytes):
            self.pool[i] ^= 0x55
        self._mix()
        return resultado


# =============================================================================
# MAC FEISTEL
# =============================================================================

class MACFeistel:
    def __init__(self, n_rodadas: int = 3):
        self.n_rodadas = n_rodadas
    
    def calcular(self, chave: bytes, dados: bytes, tamanho_mac: int) -> bytes:
        estado = bytearray(tamanho_mac)
        for i, b in enumerate(chave):
            estado[i % tamanho_mac] ^= b
        for i, b in enumerate(dados):
            estado[i % tamanho_mac] ^= b
            if (i + 1) % tamanho_mac == 0:
                self._feistel_round(estado, i)
        for _ in range(self.n_rodadas):
            self._feistel_round(estado, len(dados))
        return bytes(estado)
    
    def _feistel_round(self, estado: bytearray, contador: int):
        n = len(estado)
        for i in range(n):
            x = estado[i]
            rot = (contador + i) & 7
            x = ROT_LEFT[rot][x]
            x = x & CONST_AND[(i + contador) & 31]
            x = x | CONST_OR[(i * 3 + contador) & 31]
            x = x ^ estado[(i + 1) % n]
            estado[i] = x
    
    def verificar(self, chave: bytes, dados: bytes, mac_esperado: bytes) -> bool:
        mac_calculado = self.calcular(chave, dados, len(mac_esperado))
        resultado = 0
        for a, b in zip(mac_calculado, mac_esperado):
            resultado |= a ^ b
        return resultado == 0


# =============================================================================
# ENTROPIA COM TTL
# =============================================================================

@dataclass
class EntropiaComTTL:
    dados: bytes
    tx_criacao: int


# =============================================================================
# GERADOR DE ENTROPIA FISICA
# =============================================================================

class GeradorEntropiaFisica:
    def __init__(self, n_xor: int = 2, n_rodadas: int = 3,
                 pool_size: int = 64, pool_max: int = 128, pool_min: int = 64):
        self.n_xor = n_xor
        self.mixer = MixerFeistel(pool_size=pool_size, n_rodadas=n_rodadas)
        self.pool_max = pool_max
        self.pool_min = pool_min
        self.pool_quente: List[EntropiaComTTL] = []
        self.tx_atual = 0
        self.contador_nonce = 0
        self._trabalhos = [
            lambda: sum(range(10)), lambda: sum(range(8)),
            lambda: sum(range(12)), lambda: sum(i*i for i in range(5)),
        ]
        self._idx = 0
        self.calibrado = True
        self.bits_bons = list(range(8))
    
    def _coletar_timing(self) -> int:
        trabalho = self._trabalhos[self._idx % len(self._trabalhos)]
        self._idx += 1
        t1 = time.perf_counter_ns()
        trabalho()
        t2 = time.perf_counter_ns()
        return t2 - t1
    
    def _coletar_timing_xor(self) -> int:
        resultado = 0
        for _ in range(self.n_xor):
            resultado ^= self._coletar_timing()
        return resultado
    
    def _limpar_pool_antigo(self):
        limite = self.tx_atual - POOL_TTL
        self.pool_quente = [e for e in self.pool_quente if e.tx_criacao > limite]
    
    def _tamanho_pool(self) -> int:
        return sum(len(e.dados) for e in self.pool_quente)
    
    def atualizar_tx(self, tx: int):
        self.tx_atual = tx
        self._limpar_pool_antigo()
    
    def pre_aquecer(self, n_amostras: int = 32):
        for _ in range(n_amostras):
            timing = self._coletar_timing_xor()
            self.mixer.atualizar(timing)
        if self._tamanho_pool() < self.pool_min:
            novos = self.mixer.extrair(self.pool_min - self._tamanho_pool())
            self.pool_quente.append(EntropiaComTTL(novos, self.tx_atual))
    
    def alimentar_pool(self):
        if self._tamanho_pool() < self.pool_max:
            timing = self._coletar_timing_xor()
            self.mixer.atualizar(timing)
            if self._tamanho_pool() < self.pool_min:
                novos = self.mixer.extrair(16)
                self.pool_quente.append(EntropiaComTTL(novos, self.tx_atual))
    
    def calibrar(self, n_amostras: int = 100) -> Dict:
        self.pre_aquecer(n_amostras)
        return {'bits_bons': self.bits_bons, 'vies': {}}
    
    def gerar_bytes(self, n: int) -> bytes:
        self._limpar_pool_antigo()
        resultado = bytearray()
        while len(resultado) < n and self.pool_quente:
            entrada = self.pool_quente[0]
            dados = entrada.dados
            if len(dados) <= n - len(resultado):
                resultado.extend(dados)
                self.pool_quente.pop(0)
            else:
                falta = n - len(resultado)
                resultado.extend(dados[:falta])
                self.pool_quente[0] = EntropiaComTTL(dados[falta:], entrada.tx_criacao)
        if len(resultado) < n:
            for _ in range(max((n - len(resultado)) // 2, 16)):
                timing = self._coletar_timing_xor()
                self.mixer.atualizar(timing)
            novos = self.mixer.extrair(n - len(resultado))
            resultado.extend(novos)
        return bytes(resultado[:n])
    
    def gerar_nonce(self, tamanho: int) -> bytes:
        self.contador_nonce += 1
        timing1 = self._coletar_timing_xor()
        timing2 = self._coletar_timing_xor()
        nonce = bytearray(tamanho)
        if tamanho >= 16:
            for i in range(8):
                nonce[i] = (timing1 >> (i * 8)) & 0xFF
            contador_bytes = self.contador_nonce.to_bytes(4, 'big')
            for i in range(4):
                nonce[8 + i] = contador_bytes[i]
            for i in range(min(4, tamanho - 12)):
                nonce[12 + i] = (timing2 >> (i * 8)) & 0xFF
        else:
            contador_bytes = self.contador_nonce.to_bytes(4, 'big')
            for i in range(min(4, tamanho)):
                nonce[i] = contador_bytes[i]
            for i in range(min(4, tamanho - 4)):
                nonce[4 + i] = (timing1 >> (i * 8)) & 0xFF
        return bytes(nonce)

# =============================================================================
# CAIXA DE PRIMOS
# =============================================================================

@dataclass
class CaixaPrimos:
    id_caixa: int
    primos: List[int] = field(default_factory=list)
    primos_bytes: List[bytes] = field(default_factory=list)
    indice: int = 0
    ativa: bool = True
    ativada_em_tx: int = 0
    timeout_desativar_tx: int = 0
    
    def __post_init__(self):
        if not self.primos and self.id_caixa in PRIMOS_POR_CAIXA:
            self.primos = PRIMOS_POR_CAIXA[self.id_caixa].copy()
            self.primos_bytes = PRIMOS_BYTES_POR_CAIXA[self.id_caixa].copy()
    
    def primo_atual(self) -> int:
        return self.primos[self.indice % len(self.primos)] if self.primos else 1
    
    def primo_atual_bytes(self) -> bytes:
        if not self.primos_bytes:
            return b'\x00\x00\x00\x00\x00\x00\x00\x01'
        return self.primos_bytes[self.indice % len(self.primos_bytes)]
    
    def avancar(self, n: int = 1):
        if self.primos:
            self.indice = (self.indice + n) % len(self.primos)
    
    def posicao(self) -> int:
        return self.indice
    
    def verificar_timeout(self, tx_atual: int) -> bool:
        return self.timeout_desativar_tx > 0 and tx_atual > self.timeout_desativar_tx


# =============================================================================
# RELOGIO TRANSACIONAL
# =============================================================================

@dataclass
class Relogio:
    id: int
    tick_prime: int
    caixas: List[int]
    tick_count: int = 0
    tx_count: int = 0
    ativo: bool = True
    
    def tick(self, n: int = 1) -> bool:
        if not self.ativo:
            return False
        self.tx_count += n
        if self.tx_count >= self.tick_prime:
            self.tick_count += 1
            self.tx_count = self.tx_count % self.tick_prime
            return True
        return False


# =============================================================================
# PERFIL DE HARDWARE
# =============================================================================

@dataclass
class PerfilHardware:
    vies_bits: List[float] = field(default_factory=list)
    timing_medio: float = 0.0
    timing_std: float = 0.0
    
    def similaridade(self, outro: 'PerfilHardware') -> float:
        if not self.vies_bits or not outro.vies_bits:
            return 0.0
        diff_vies = sum(abs(a - b) for a, b in zip(self.vies_bits, outro.vies_bits))
        sim_vies = 1.0 - (diff_vies / len(self.vies_bits))
        sim_timing = max(0, 1.0 - abs(self.timing_medio - outro.timing_medio) / max(self.timing_medio, 1)) if self.timing_medio > 0 else 0.5
        sim_std = max(0, 1.0 - abs(self.timing_std - outro.timing_std) / max(self.timing_std, 1)) if self.timing_std > 0 else 0.5
        return (sim_vies * 0.4) + (sim_timing * 0.3) + (sim_std * 0.3)
    
    def to_bytes(self) -> bytes:
        data = bytearray()
        for v in self.vies_bits:
            data.extend(struct.pack('>f', v))
        data.extend(struct.pack('>f', self.timing_medio))
        data.extend(struct.pack('>f', self.timing_std))
        return bytes(data)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'PerfilHardware':
        vies_bits = [struct.unpack('>f', data[i*4:(i+1)*4])[0] for i in range(8)]
        timing_medio = struct.unpack('>f', data[32:36])[0]
        timing_std = struct.unpack('>f', data[36:40])[0]
        return cls(vies_bits, timing_medio, timing_std)


class PerfiladorHardware:
    def __init__(self, n_amostras: int = 1000):
        self.n_amostras = n_amostras
        self.perfil_baseline: Optional[PerfilHardware] = None
    
    def _coletar_timing(self) -> int:
        t1 = time.perf_counter_ns()
        _ = sum(range(10))
        t2 = time.perf_counter_ns()
        return t2 - t1
    
    def capturar_perfil(self) -> PerfilHardware:
        amostras = [self._coletar_timing() for _ in range(self.n_amostras)]
        vies_bits = [sum(1 for a in amostras if (a >> bit) & 1 == 1) / len(amostras) for bit in range(8)]
        timing_medio = sum(amostras) / len(amostras)
        variance = sum((x - timing_medio) ** 2 for x in amostras) / len(amostras)
        return PerfilHardware(vies_bits, timing_medio, variance ** 0.5)
    
    def calibrar(self) -> PerfilHardware:
        self.perfil_baseline = self.capturar_perfil()
        return self.perfil_baseline
    
    def verificar_anomalia(self, limiar: float = 0.7) -> Tuple[bool, float]:
        if self.perfil_baseline is None:
            self.calibrar()
        perfil_atual = self.capturar_perfil()
        similaridade = self.perfil_baseline.similaridade(perfil_atual)
        return similaridade < limiar, similaridade


# =============================================================================
# GERENCIADOR DE AMEACAS
# =============================================================================

class GerenciadorAmeacas:
    def __init__(self, tav: 'TAVCrypto'):
        self.tav = tav
        self.falhas_mac_consecutivas = 0
        self.tx_desde_verificacao = 0
        self.historico: List[Dict] = []
    
    def registrar_ameaca(self, tipo: str, severidade: int, detalhes: str = ""):
        self.historico.append({'tipo': tipo, 'severidade': severidade, 'tx': self.tav.tx_count_global, 'detalhes': detalhes})
        if severidade >= 2:
            novo_nivel = min(NivelSeguranca.MILITARY, NivelSeguranca(self.tav.nivel_base + severidade - 1))
            self.tav._escalar_nivel(novo_nivel, timeout_tx=1000)
    
    def verificar_perfil_hardware(self, similaridade: float):
        if similaridade < 0.5:
            self.registrar_ameaca("HARDWARE_MUITO_DIFERENTE", 3, f"Similaridade: {similaridade:.2f}")
        elif similaridade < 0.7:
            self.registrar_ameaca("HARDWARE_DIFERENTE", 1, f"Similaridade: {similaridade:.2f}")
    
    def registrar_falha_mac(self):
        self.falhas_mac_consecutivas += 1
        if self.falhas_mac_consecutivas >= 3:
            self.registrar_ameaca("FALHAS_MAC_CONSECUTIVAS", 2, f"Falhas: {self.falhas_mac_consecutivas}")
    
    def resetar_falhas_mac(self):
        self.falhas_mac_consecutivas = 0
    
    def verificar_taxa_uso(self, tx_atual: int):
        self.tx_desde_verificacao += 1
    
    def verificar_timeouts_caixas(self, tx_atual: int):
        config = CONFIG_POR_NIVEL[self.tav.nivel_base]
        caixas_iniciais = set(config['caixas_iniciais'])
        for idx, caixa in self.tav.caixas.items():
            if idx not in caixas_iniciais and caixa.ativa and caixa.verificar_timeout(tx_atual):
                caixa.ativa = False
                caixa.timeout_desativar_tx = 0

# =============================================================================
# SISTEMA TAV V9.3 PRINCIPAL
# =============================================================================

class TAVCrypto:
    """
    Sistema TAV Clock Cryptography V9.3
    
    Prime Boxes (1,464 total):
    - Box 1: 21 primes (2 digits: 11-97)
    - Box 2: 143 primes (3 digits: 101-997)
    - Box 3: 500 primes (4 digits: 1009-4993)
    - Box 4: 500 primes (5 digits: 10007-14759)
    - Box 5: 200 primes (7 digits: 1000003-1002583)
    - Box 6: 100 primes (9 digits: 100000007-100001819)
    
    Novidades sobre V9.2:
    1. Checkpoint automatico a cada 10.000 transacoes
    2. Checkpoint hardcoded (caminho fixo, oculto)
    3. Checkpoint criptografado pelo proprio TAV
    4. Restauracao automatica na inicializacao
    5. Deteccao de hardware diferente (aviso, nao bloqueio)
    """
    
    VERSION = "9.3"
    
    def __init__(self, senha_ou_seed, nivel=NivelSeguranca.CONSUMER, instance_id: str = 'default'):
        if isinstance(nivel, str):
            nivel = NivelSeguranca[nivel.upper()]
        
        self.nivel_base = nivel
        self.nivel_atual = nivel
        self.nivel_timeout_tx = 0
        self.config = CONFIG_POR_NIVEL[nivel]
        self.tx_count_global = 0
        self.boot_count = 0
        self.instance_id = instance_id
        self._checkpoint_path = _get_checkpoint_path(instance_id)
        self._ultimo_checkpoint_tx = 0
        self._seed_original = senha_ou_seed
        
        # V9.3: Derivar chave de checkpoint da seed (PRIMEIRO, antes de qualquer entropia)
        self._checkpoint_key = self._derivar_chave_checkpoint(senha_ou_seed)
        
        # 1. Perfil de hardware
        self.perfilador = PerfiladorHardware(n_amostras=500)
        self.perfil_baseline = self.perfilador.calibrar()
        
        # 2. Gerador de entropia
        self.entropia = GeradorEntropiaFisica(
            n_xor=self.config['n_xor'], n_rodadas=self.config['n_rodadas_mixer'],
            pool_max=self.config['pool_max'], pool_min=self.config['pool_min']
        )
        self.entropia.calibrar()
        
        # 3. MAC-Feistel
        self.mac = MACFeistel(n_rodadas=self.config['n_rodadas_mac'])
        
        # 4. Caixas de primos
        self.caixas: Dict[int, CaixaPrimos] = {}
        for idx in range(1, 7):
            caixa = CaixaPrimos(id_caixa=idx)
            caixa.ativa = idx in self.config['caixas_iniciais']
            self.caixas[idx] = caixa
        
        # 5. Relogios
        self.relogios: List[Relogio] = []
        for cfg in RELOGIOS_CONFIG:
            self.relogios.append(Relogio(id=cfg['id'], tick_prime=cfg['tick_prime'], caixas=cfg['caixas']))
        for i, relogio in enumerate(self.relogios):
            relogio.ativo = (i < nivel)
        
        # 6. Gerenciador de ameacas
        self.ameacas = GerenciadorAmeacas(self)
        
        # 7. Master entropy (sera sobrescrito se checkpoint existir)
        self.master_entropy = self._inicializar_master_entropy(senha_ou_seed)
        
        # 8. Estado
        self.ultima_tx = 0
        self.log_anomalias: List[Dict] = []
        self._hardware_diferente = False
        
        # 9. V9.3: Restaura checkpoint (pode sobrescrever master_entropy)
        self._restaurar_checkpoint()
    
    def _derivar_chave_checkpoint(self, senha_ou_seed) -> bytes:
        """Deriva chave fixa para checkpoint - baseada apenas na seed."""
        seed_words = senha_ou_seed.split() if isinstance(senha_ou_seed, str) else senha_ou_seed
        seed_bytes = (' '.join(seed_words) + '_TAV_CHECKPOINT_KEY_V93').encode('utf-8')
        tamanho = 32
        chave = bytearray(tamanho)
        for i, b in enumerate(seed_bytes):
            chave[i % tamanho] ^= b
        for rodada in range(4):
            for i in range(tamanho):
                chave[i] = ROT_LEFT[(rodada + i) & 7][chave[i]] ^ chave[(i + 1) % tamanho]
        return bytes(chave)
    
    def _escalar_nivel(self, novo_nivel: NivelSeguranca, timeout_tx: int):
        if novo_nivel > self.nivel_atual:
            self.nivel_atual = novo_nivel
            self.nivel_timeout_tx = self.tx_count_global + timeout_tx
            self.config = CONFIG_POR_NIVEL[novo_nivel]
            for i, relogio in enumerate(self.relogios):
                relogio.ativo = (i < novo_nivel)
    
    def _verificar_desescalar_nivel(self):
        if self.nivel_atual > self.nivel_base and self.tx_count_global > self.nivel_timeout_tx:
            self.nivel_atual = self.nivel_base
            self.config = CONFIG_POR_NIVEL[self.nivel_base]
            self.nivel_timeout_tx = 0
            for i, relogio in enumerate(self.relogios):
                relogio.ativo = (i < self.nivel_base)
    
    def _inicializar_master_entropy(self, senha_ou_seed) -> bytes:
        seed_words = senha_ou_seed.split() if isinstance(senha_ou_seed, str) else senha_ou_seed
        seed_bytes = ' '.join(seed_words).encode('utf-8')
        tamanho = self.config['master_entropy']
        seed_normalized = bytearray(tamanho)
        for i, b in enumerate(seed_bytes):
            seed_normalized[i % tamanho] ^= b
        clock_entropy = self.entropia.gerar_bytes(tamanho * 2)
        master = bytearray(tamanho * 2)
        for i in range(tamanho):
            master[i] = seed_normalized[i] ^ clock_entropy[i]
        for i in range(tamanho, tamanho * 2):
            master[i] = clock_entropy[i]
        return bytes(master)
    
    def _derivar_chave(self) -> bytes:
        relogios_ativos = [r for r in self.relogios if r.ativo]
        state_sum = sum(r.tick_count * 1000 + r.tx_count for r in relogios_ativos)
        tamanho_chave = self.config['chave_bytes']
        tamanho_master = len(self.master_entropy)
        offset = (state_sum * 7) % max(1, tamanho_master - tamanho_chave)
        chave = bytearray(self.master_entropy[offset:offset + tamanho_chave])
        while len(chave) < tamanho_chave:
            chave.extend(self.master_entropy)
        chave = chave[:tamanho_chave]
        for relogio in relogios_ativos:
            for idx_caixa in relogio.caixas:
                if idx_caixa in self.caixas and self.caixas[idx_caixa].ativa:
                    primo_bytes = self.caixas[idx_caixa].primo_atual_bytes()
                    for j, b in enumerate(primo_bytes):
                        chave[(relogio.id * 8 + j) % tamanho_chave] ^= b
        return bytes(chave)
    
    def _gerar_keystream(self, chave: bytes, nonce: bytes, tamanho: int) -> bytes:
        keystream = bytearray(tamanho)
        tamanho_chave, tamanho_nonce = len(chave), len(nonce)
        for i in range(tamanho):
            keystream[i] = ROT_LEFT[i & 7][chave[i % tamanho_chave]] ^ nonce[i % tamanho_nonce] ^ (i & 0xFF)
        return bytes(keystream)
    
    def _tick_interno(self, n: int = 1):
        self.tx_count_global += n
        self.ultima_tx = self.tx_count_global
        self.entropia.atualizar_tx(self.tx_count_global)
        self.entropia.alimentar_pool()
        intervalo = VERIFICACAO_POR_NIVEL[self.nivel_atual]
        if self.tx_count_global % intervalo == 0:
            self.ameacas.verificar_taxa_uso(self.tx_count_global)
            self.ameacas.verificar_timeouts_caixas(self.tx_count_global)
            self._verificar_desescalar_nivel()
        for relogio in self.relogios:
            if relogio.tick(n):
                for idx_caixa in relogio.caixas:
                    if idx_caixa in self.caixas and self.caixas[idx_caixa].ativa:
                        self.caixas[idx_caixa].avancar()
        if self.tx_count_global % 100 == 0 and 5 in self.caixas and self.caixas[5].ativa:
            self.caixas[5].avancar()
        if self.tx_count_global % 1000 == 0 and 6 in self.caixas and self.caixas[6].ativa:
            self.caixas[6].avancar()
        # V9.3: Checkpoint automatico
        if self.tx_count_global - self._ultimo_checkpoint_tx >= CHECKPOINT_INTERVAL:
            self._salvar_checkpoint()
    
    # =========================================================================
    # V9.3: CHECKPOINT
    # =========================================================================
    
    def _serializar_estado(self) -> bytes:
        data = bytearray()
        data.extend(CHECKPOINT_VERSION)  # 5 bytes
        data.extend(struct.pack('>Q', self.tx_count_global))  # 8 bytes
        data.extend(struct.pack('>I', self.boot_count))  # 4 bytes
        data.append(self.nivel_base)  # 1 byte
        data.extend(struct.pack('>H', len(self.master_entropy)))  # 2 bytes
        data.extend(self.master_entropy)
        data.append(len(self.relogios))
        for rel in self.relogios:
            data.extend(struct.pack('>II', rel.tick_count, rel.tx_count))
        data.append(len(self.caixas))
        for idx in sorted(self.caixas.keys()):
            data.append(idx)
            data.extend(struct.pack('>I', self.caixas[idx].indice))
            data.append(1 if self.caixas[idx].ativa else 0)
        data.extend(self.perfil_baseline.to_bytes())  # 40 bytes
        data.extend(struct.pack('>Q', self.entropia.contador_nonce))  # 8 bytes
        return bytes(data)
    
    def _deserializar_estado(self, data: bytes) -> bool:
        try:
            pos = 0
            if data[pos:pos+5] != CHECKPOINT_VERSION:
                return False
            pos += 5
            self.tx_count_global = struct.unpack('>Q', data[pos:pos+8])[0]
            pos += 8
            self.boot_count = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
            pos += 1  # nivel_base (ignorado)
            master_len = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2
            self.master_entropy = data[pos:pos+master_len]
            pos += master_len
            n_relogios = data[pos]
            pos += 1
            for i in range(min(n_relogios, len(self.relogios))):
                self.relogios[i].tick_count, self.relogios[i].tx_count = struct.unpack('>II', data[pos:pos+8])
                pos += 8
            n_caixas = data[pos]
            pos += 1
            for _ in range(n_caixas):
                idx = data[pos]
                pos += 1
                indice = struct.unpack('>I', data[pos:pos+4])[0]
                pos += 4
                pos += 1  # ativa (ignorado)
                if idx in self.caixas:
                    self.caixas[idx].indice = indice
            perfil_salvo = PerfilHardware.from_bytes(data[pos:pos+40])
            pos += 40
            similaridade = self.perfil_baseline.similaridade(perfil_salvo)
            if similaridade < 0.7:
                self._hardware_diferente = True
                self.registrar_anomalia("HARDWARE_DIFERENTE_CHECKPOINT", f"Similaridade: {similaridade:.2f}")
            self.entropia.contador_nonce = struct.unpack('>Q', data[pos:pos+8])[0]
            return True
        except Exception as e:
            self.registrar_anomalia("CHECKPOINT_DESERIALIZE_ERROR", str(e))
            return False
    
    def _salvar_checkpoint(self):
        try:
            estado_enc = self._encrypt_interno(self._serializar_estado())
            self._checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self._checkpoint_path.with_suffix('.tmp')
            with open(temp_path, 'wb') as f:
                f.write(estado_enc)
            temp_path.replace(self._checkpoint_path)
            self._ultimo_checkpoint_tx = self.tx_count_global
        except Exception as e:
            self.registrar_anomalia("CHECKPOINT_SAVE_ERROR", str(e))
    
    def _restaurar_checkpoint(self):
        try:
            if not self._checkpoint_path.exists():
                self.boot_count = 1
                return
            with open(self._checkpoint_path, 'rb') as f:
                estado_enc = f.read()
            estado, ok = self._decrypt_interno(estado_enc)
            if not ok:
                self.registrar_anomalia("CHECKPOINT_DECRYPT_FAILED", "Iniciando do zero")
                self.boot_count = 1
                return
            if self._deserializar_estado(estado):
                self.boot_count += 1
                self._ultimo_checkpoint_tx = self.tx_count_global
            else:
                self.boot_count = 1
        except Exception as e:
            self.registrar_anomalia("CHECKPOINT_RESTORE_ERROR", str(e))
            self.boot_count = 1
    
    def _encrypt_interno(self, plaintext: bytes) -> bytes:
        """Encrypt para checkpoint - usa chave derivada da seed."""
        chave = self._checkpoint_key
        nonce = self.entropia.gerar_nonce(16)  # Nonce fixo de 16 bytes para checkpoint
        keystream = self._gerar_keystream(chave, nonce, len(plaintext))
        ciphertext = bytes(d ^ k for d, k in zip(plaintext, keystream))
        mac = self.mac.calcular(chave, nonce + ciphertext, 16)  # MAC de 16 bytes
        return nonce + mac + ciphertext
    
    def _decrypt_interno(self, dados_completos: bytes) -> Tuple[bytes, bool]:
        """Decrypt para checkpoint - usa chave derivada da seed."""
        tamanho_nonce, tamanho_mac = 16, 16  # Fixos para checkpoint
        if len(dados_completos) < tamanho_nonce + tamanho_mac:
            return b'', False
        nonce = dados_completos[:tamanho_nonce]
        mac_recebido = dados_completos[tamanho_nonce:tamanho_nonce + tamanho_mac]
        ciphertext = dados_completos[tamanho_nonce + tamanho_mac:]
        chave = self._checkpoint_key
        if not self.mac.verificar(chave, nonce + ciphertext, mac_recebido):
            return b'', False
        keystream = self._gerar_keystream(chave, nonce, len(ciphertext))
        return bytes(c ^ k for c, k in zip(ciphertext, keystream)), True
    
    # =========================================================================
    # API PUBLICA
    # =========================================================================
    
    def encrypt(self, plaintext: bytes, auto_tick: bool = True) -> bytes:
        """Encripta dados."""
        tx_atual = self.tx_count_global
        chave = self._derivar_chave()
        nonce = self.entropia.gerar_nonce(self.config['nonce_bytes'])
        metadata = bytes([0x93, self.nivel_atual]) + struct.pack('>Q', tx_atual)[:6]
        dados = metadata + plaintext
        keystream = self._gerar_keystream(chave, nonce, len(dados))
        ciphertext = bytes(d ^ k for d, k in zip(dados, keystream))
        mac = self.mac.calcular(chave, nonce + ciphertext, self.config['mac_bytes'])
        if auto_tick:
            self._tick_interno()
        return nonce + mac + ciphertext
    
    def decrypt(self, dados_completos: bytes) -> Tuple[bytes, bool]:
        """Decripta dados."""
        tamanho_nonce, tamanho_mac = self.config['nonce_bytes'], self.config['mac_bytes']
        if len(dados_completos) < tamanho_nonce + tamanho_mac + 8:
            return b'', False
        nonce = dados_completos[:tamanho_nonce]
        mac_recebido = dados_completos[tamanho_nonce:tamanho_nonce + tamanho_mac]
        ciphertext = dados_completos[tamanho_nonce + tamanho_mac:]
        chave = self._derivar_chave()
        if not self.mac.verificar(chave, nonce + ciphertext, mac_recebido):
            self.ameacas.registrar_falha_mac()
            return b'', False
        self.ameacas.resetar_falhas_mac()
        keystream = self._gerar_keystream(chave, nonce, len(ciphertext))
        dados = bytes(c ^ k for c, k in zip(ciphertext, keystream))
        return dados[8:] if len(dados) >= 8 else b'', len(dados) >= 8
    
    def tick(self, n: int = 1) -> Dict:
        """Avanca estado manualmente."""
        self._tick_interno(n)
        return {'tx_global': self.tx_count_global, 'disparados': [r.id for r in self.relogios if r.tick_count > 0]}
    
    def verificar_hardware(self) -> Tuple[bool, float]:
        """Verifica se ainda estamos no mesmo hardware."""
        e_anomalia, similaridade = self.perfilador.verificar_anomalia()
        self.ameacas.verificar_perfil_hardware(similaridade)
        return not e_anomalia, similaridade
    
    def verificar_dead_man(self, limite: int = 10000) -> bool:
        """Verifica dead man switch."""
        if self.tx_count_global - self.ultima_tx > limite:
            self.master_entropy = bytes(len(self.master_entropy))
            return False
        return True
    
    def forcar_checkpoint(self):
        """Forca salvamento de checkpoint."""
        self._salvar_checkpoint()
    
    def status(self) -> Dict:
        """Retorna status do sistema."""
        return {
            'versao': f'V{self.VERSION}',
            'nivel_base': self.nivel_base.name,
            'nivel_atual': self.nivel_atual.name,
            'tx_global': self.tx_count_global,
            'boot_count': self.boot_count,
            'ultimo_checkpoint_tx': self._ultimo_checkpoint_tx,
            'checkpoint_interval': CHECKPOINT_INTERVAL,
            'hardware_diferente': self._hardware_diferente,
            'relogios_ativos': sum(1 for r in self.relogios if r.ativo),
            'caixas_ativas': [idx for idx, c in self.caixas.items() if c.ativa],
            'primos_por_caixa': {idx: len(c.primos) for idx, c in self.caixas.items()},
            'total_primos': sum(len(c.primos) for c in self.caixas.values()),
            'n_xor': self.entropia.n_xor,
            'tamanho_chave': self.config['chave_bits'],
            'tamanho_mac': self.config['mac_bytes'],
            'pool_quente': self.entropia._tamanho_pool(),
            'ameacas_detectadas': len(self.ameacas.historico),
            'checkpoint_path': str(self._checkpoint_path),
        }
    
    def registrar_anomalia(self, tipo: str, detalhes: str = ""):
        """Registra evento anomalo."""
        self.log_anomalias.append({'tipo': tipo, 'tx_global': self.tx_count_global, 'detalhes': detalhes})


# Aliases
TAVCryptoV93 = TAVCrypto
TAV = TAVCrypto


# =============================================================================
# DEMONSTRACAO
# =============================================================================

def demo():
    """Demonstracao do TAV V9.3."""
    print("=" * 70)
    print("TAV CLOCK CRYPTOGRAPHY V9.3 - COM CHECKPOINT AUTOMATICO")
    print("=" * 70)
    print("\nV9.3 Features:")
    print("   - 1,464 prime numbers across 6 boxes")
    print("   - Automatic checkpoint every 10,000 transactions")
    print("   - Encrypted checkpoint (self-protecting)")
    print("   - Automatic restoration on initialization")
    print("   - Hardware change detection")
    
    print("\n1. INITIALIZATION")
    print("-" * 50)
    tav = TAV("minha senha super secreta para teste", nivel="consumer", instance_id="demo")
    for k, v in tav.status().items():
        print(f"   {k}: {v}")
    
    print("\n2. ENCRYPT/DECRYPT")
    print("-" * 50)
    mensagem = b"TAV V9.3 - With 1,464 primes!"
    print(f"   Original:    {mensagem}")
    ciphertext = tav.encrypt(mensagem, auto_tick=False)
    print(f"   Ciphertext:  {len(ciphertext)} bytes")
    plaintext, ok = tav.decrypt(ciphertext)
    print(f"   Decrypted:   {plaintext}")
    print(f"   Match:       {mensagem == plaintext}")
    tav.tick()
    
    print("\n3. CHECKPOINT SIMULATION")
    print("-" * 50)
    print(f"   Running 100 transactions...")
    for i in range(100):
        tav.encrypt(b"teste" * 20, auto_tick=True)
    print(f"   TX count: {tav.tx_count_global}")
    
    print("\n4. FORCE CHECKPOINT")
    print("-" * 50)
    tav.forcar_checkpoint()
    print(f"   Checkpoint saved to: {tav._checkpoint_path}")
    print(f"   File exists: {tav._checkpoint_path.exists()}")
    if tav._checkpoint_path.exists():
        print(f"   Size: {tav._checkpoint_path.stat().st_size} bytes")
    
    print("\n5. BENCHMARK")
    print("-" * 50)
    import time as time_module
    dados_teste = b"X" * 1024
    n_ops = 500
    inicio = time_module.perf_counter()
    for _ in range(n_ops):
        tav.encrypt(dados_teste, auto_tick=False)
    tempo_total = time_module.perf_counter() - inicio
    print(f"   {n_ops} encrypts of 1KB in {tempo_total:.3f}s")
    print(f"   Throughput: {(n_ops * 1024) / tempo_total / 1024:.1f} KB/s")
    
    print("\n" + "=" * 70)
    print("DEMO V9.3 COMPLETE")
    print("=" * 70)


def test_checkpoint_restore():
    """Test checkpoint restoration."""
    print("\n" + "=" * 70)
    print("CHECKPOINT RESTORATION TEST")
    print("=" * 70)
    
    seed = "teste checkpoint restauracao"
    instance = "test_restore"
    
    print("\n1. Creating first instance...")
    tav1 = TAV(seed, nivel="consumer", instance_id=instance)
    print(f"   Boot count: {tav1.boot_count}, TX: {tav1.tx_count_global}")
    print(f"   Total primes: {tav1.status()['total_primos']}")
    
    print("\n2. Running 50 transactions...")
    for i in range(50):
        tav1.encrypt(f"msg {i}".encode(), auto_tick=True)
    tx_antes = tav1.tx_count_global
    boot_antes = tav1.boot_count
    
    print(f"   TX after: {tx_antes}")
    
    print("\n3. Forcing checkpoint...")
    tav1.forcar_checkpoint()
    del tav1
    
    print("\n4. Creating new instance (reboot)...")
    tav2 = TAV(seed, nivel="consumer", instance_id=instance)
    print(f"   Boot count: {tav2.boot_count} (was {boot_antes})")
    print(f"   TX restored: {tav2.tx_count_global} (was {tx_antes})")
    
    if tav2.tx_count_global == tx_antes and tav2.boot_count == boot_antes + 1:
        print("\nCHECKPOINT RESTORED SUCCESSFULLY!")
    else:
        print("\nRESTORATION FAILED")
    
    try:
        tav2._checkpoint_path.unlink()
    except:
        pass
    print("=" * 70)


if __name__ == "__main__":
    demo()
    test_checkpoint_restore()
