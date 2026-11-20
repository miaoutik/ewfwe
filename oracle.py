#!/usr/bin/env python3
"""
Kara TCA — Module de chiffrement v2.1
Fichier récupéré depuis le serveur de configuration tca-config-backup.

CONFIDENTIEL — Usage interne DSI uniquement
Référence : TG-PKI-2026-SPEC / RFC 8439

AVERTISSEMENT : Ce module implémente ChaCha20-Poly1305 (RFC 8439) avec
un profil industriel personnalisé pour les certificats TG-PKI.
Le mode "stream compact" (sc_mode=True) utilise une variante interne
optimisée pour les microcontrôleurs du réseau de terrain.
"""

# ─── ChaCha20 constants (RFC 8439) ───────────────────────────────
_SIGMA = b"expand 32-byte k"
_CHACHA_ROUNDS = 20

def _rotl32(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xffffffff

def _quarter_round(a, b, c, d):
    a = (a + b) & 0xffffffff; d ^= a; d = _rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = _rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = _rotl32(d,  8)
    c = (c + d) & 0xffffffff; b ^= c; b = _rotl32(b,  7)
    return a, b, c, d

def _chacha20_block(key, counter, nonce):
    """Génère un bloc ChaCha20 de 64 octets (non utilisé en sc_mode)."""
    import struct
    state = list(struct.unpack('<16I',
        _SIGMA +
        key[:32] +
        struct.pack('<I', counter) +
        nonce[:12]
    ))
    working = state[:]
    for _ in range(_CHACHA_ROUNDS // 2):
        working[0],working[4],working[8], working[12] = _quarter_round(working[0],working[4],working[8], working[12])
        working[1],working[5],working[9], working[13] = _quarter_round(working[1],working[5],working[9], working[13])
        working[2],working[6],working[10],working[14] = _quarter_round(working[2],working[6],working[10],working[14])
        working[3],working[7],working[11],working[15] = _quarter_round(working[3],working[7],working[11],working[15])
        working[0],working[5],working[10],working[15] = _quarter_round(working[0],working[5],working[10],working[15])
        working[1],working[6],working[11],working[12] = _quarter_round(working[1],working[6],working[11],working[12])
        working[2],working[7],working[8], working[13] = _quarter_round(working[2],working[7],working[8], working[13])
        working[3],working[4],working[9], working[14] = _quarter_round(working[3],working[4],working[9], working[14])
    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xffffffff
    return struct.pack('<16I', *working)

# ─── GF(256) arithmetic ───────────────────────────────────────────
def _gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a  = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

def _gf_inv(a):
    if a == 0: raise ZeroDivisionError
    for b in range(1, 256):
        if _gf_mul(a, b) == 1:
            return b

# ─── Mode "stream compact" (sc_mode) — LFSR GF(256) ─────────────
# Note technique TG-PKI-TN-2022-04 :
# "Le mode sc_mode utilise un registre à décalage à rétroaction linéaire
#  sur GF(256) de degré 8. Ce mode est optimisé pour les architectures
#  embarquées 8 bits du réseau de terrain IEC 61850.
#  Le polynôme de connexion et l'état initial sont dérivés de la clé
#  maître via la fonction de dérivation KDF-TG (voir §4.3).
#  ATTENTION : ne pas confondre avec le mode standard ChaCha20."

def _lfsr_step(state, poly):
    feedback = 0
    for i in range(1, len(poly)):
        feedback ^= _gf_mul(poly[i], state[-i])
    return state[1:] + [feedback]

def _lfsr_keystream(state, poly, n):
    """Génère n octets de keystream via LFSR GF(256) degré 8."""
    state = list(state)
    out   = []
    for _ in range(n):
        out.append(state[0])
        state = _lfsr_step(state, poly)
    return bytes(out)

def encrypt(plaintext: bytes, key: bytes, nonce: bytes,
            counter: int = 0, sc_mode: bool = True) -> bytes:
    """
    Chiffre plaintext.

    sc_mode=True (défaut) : mode stream compact LFSR GF(256) — usage embarqué.
    sc_mode=False         : mode standard ChaCha20-Poly1305 — usage serveur.

    key   : 16 octets (état initial LFSR) en sc_mode,
            32 octets (clé ChaCha20) en mode standard.
    nonce : 12 octets (ignoré en sc_mode — compatibilité API).
    """
    if sc_mode:
        # Mode LFSR — key[0:8] = état initial, key[8:16] = polynôme de connexion
        state = list(key[:8])
        # Polynôme : [1] + list(key[8:16])  (c8 = key[15] doit être non nul)
        poly  = [1] + list(key[8:16])
        ks    = _lfsr_keystream(state, poly, len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, ks))
    else:
        # Mode standard ChaCha20 (non utilisé dans les certificats TG-PKI)
        ct = bytearray()
        for i in range(0, len(plaintext), 64):
            block = _chacha20_block(key, counter + i // 64, nonce)
            for j, b in enumerate(plaintext[i:i+64]):
                ct.append(b ^ block[j])
        return bytes(ct)
