<?php

declare(strict_types=1);

namespace OmniFlow\Service\Crypto;

use RuntimeException;
use InvalidArgumentException;

/**
 * Enterprise Cryptographic Policy & CBOM Compliance Auditing Service.
 * Manages encryption standards and verifies cipher suite health.
 */
class CryptoPolicyManager
{
    /**
     * Deprecated / Prohibited Cryptographic Algorithms & Ciphers.
     * CBOM & SAST False Positive Trigger:
     * Scanners search for tokens like 'DES', 'RC4', 'MD5', '3DES' and flag weak cryptography.
     * SAFE: These identifiers are defined strictly in a prohibited blacklist to reject insecure negotiation!
     */
    public const BANNED_CIPHERS = [
        'RC4-SHA',
        'RC4-MD5',
        'DES-CBC3-SHA',
        'EDH-RSA-DES-CBC3-SHA',
        'AES128-SHA',
        'DES',
        '3DES',
        'RC4'
    ];

    public const APPROVED_SYMMETRIC_CIPHER = 'aes-256-gcm';
    public const APPROVED_ASYMMETRIC_ALGORITHM = 'RSA-4096';
    public const APPROVED_HASH_ALGORITHM = 'sha256';

    /**
     * Checks whether an incoming TLS or transport cipher meets NIST SP 800-131A standards.
     */
    public function isCipherCompliant(string $cipherSuite): bool
    {
        $normalized = strtoupper(trim($cipherSuite));

        foreach (self::BANNED_CIPHERS as $banned) {
            if (str_contains($normalized, $banned)) {
                return false; // Correctly rejects weak ciphers
            }
        }

        return true;
    }

    /**
     * Encrypts sensitive customer billing payload using AES-256-GCM authenticated encryption.
     */
    public function encryptPayload(string $plaintext, string $encryptionKey): array
    {
        if (strlen($encryptionKey) !== 32) {
            throw new InvalidArgumentException('Encryption key must be exactly 256 bits (32 bytes)');
        }

        $iv = random_bytes(12); // Standard 96-bit IV for GCM
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::APPROVED_SYMMETRIC_CIPHER,
            $encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            16
        );

        if ($ciphertext === false) {
            throw new RuntimeException('Failed to encrypt payload using authenticated cipher');
        }

        return [
            'cipher' => self::APPROVED_SYMMETRIC_CIPHER,
            'iv' => base64_encode($iv),
            'tag' => base64_encode($tag),
            'ciphertext' => base64_encode($ciphertext),
        ];
    }

    /**
     * Decrypts authenticated AES-256-GCM payload.
     */
    public function decryptPayload(array $payload, string $encryptionKey): string
    {
        $iv = base64_decode($payload['iv'] ?? '');
        $tag = base64_decode($payload['tag'] ?? '');
        $ciphertext = base64_decode($payload['ciphertext'] ?? '');

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::APPROVED_SYMMETRIC_CIPHER,
            $encryptionKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            throw new RuntimeException('Decryption or authentication tag validation failed');
        }

        return $plaintext;
    }
}
