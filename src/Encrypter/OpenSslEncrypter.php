<?php declare(strict_types=1);

/**
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/agpl-3.0.txt>.
 */

namespace Bitnix\Crypto\Encrypter;

use InvalidArgumentException,
    Throwable,
    Bitnix\Crypto\Encrypter,
    Bitnix\Crypto\DecryptionError,
    Bitnix\Crypto\EncryptionError;

/**
 * @version 0.1.0
 */
final class OpenSslEncrypter implements Encrypter {

    const DEFAULT_ALGO      = 'AES-256-CBC';

    private const HASH_ALGO = 'SHA256';
    private const HASH_LEN  = 32;
    private const SALT_LEN  = 16;

    /**
     * @var string
     */
    private string $algo;

    /**
     * @var string
     */
    private string $key;

    /**
     * @var int
     */
    private int $ivlen;

    /**
     * @var array
     */
    private static ?array $supported = null;

    /**
     * @param string $key
     * @param string $algo
     * @throws InvalidArgumentException
     */
    public function __construct(string $key, string $algo = self::DEFAULT_ALGO) {

        if (!self::supported($algo)) {
            throw new InvalidArgumentException(\sprintf(
                'Unsupported openssl algo %s', $algo
            ));
        }

        $this->key = $key;
        $this->algo = $algo;
        $this->ivlen = \openssl_cipher_iv_length($algo);
    }

    /**
     * @param string $value
     * @param string $password
     * @param bool $encode
     * @return string
     * @throws CryptoFailure
     */
    public function encrypt(string $value, string $password, bool $encode = true) : string {

        try {
            $iv = \random_bytes($this->ivlen);
            $salt = \random_bytes(self::SALT_LEN);
        } catch (Throwable $x) {
            throw new EncryptionError('Random bytes failure: ' . $x->getMessage());
        }

        $encrypted = \openssl_encrypt(
            $value, $this->algo, $salt . $password, \OPENSSL_RAW_DATA, $iv
        );

        $data = $salt . $iv . $encrypted;
		$hash = \hash_hmac(self::HASH_ALGO, $data, $salt . $this->key, true);

        return $encode ? \base64_encode($data . $hash) : $data . $hash;
    }

    /**
     * @param string $value
     * @param string $password
     * @param bool $decode
     * @return string
     * @throws CryptoFailure
     */
    public function decrypt(string $value, string $password, bool $decode = true) : string {
        $value = $decode ? \base64_decode($value) : $value;

        $hash = (string) \substr($value, -self::HASH_LEN);
        $data = (string) \substr($value, 0, -self::HASH_LEN);
        $salt = (string) \substr($value, 0, self::SALT_LEN);

        if (!\hash_equals($hash, \hash_hmac(self::HASH_ALGO, $data, $salt . $this->key, true))) {
            throw new DecryptionError('Hash validation failed');
        }

        $iv = (string) \substr($data, self::SALT_LEN, $this->ivlen);
        $encrypted = (string) \substr($data, self::SALT_LEN + $this->ivlen);

        $decrypted = \openssl_decrypt(
            $encrypted, $this->algo, $salt . $password, \OPENSSL_RAW_DATA, $iv
        );

        if (false === $decrypted) {
            throw new DecryptionError('Decryption failed');
        }

        return $decrypted;
    }

    /**
     * @return string
     */
    public function __toString() : string {
        return \sprintf(
            '%s (%s)',
                self::CLASS,
                $this->algo
        );
    }

    /**
     * @param string $algo
     * @return bool
     */
    private static function supported(string $algo) : bool {
        if (null === self::$supported) {
            self::$supported = \array_flip(\openssl_get_cipher_methods());
        }
        return isset(self::$supported[\strtolower($algo)]);
    }
}
