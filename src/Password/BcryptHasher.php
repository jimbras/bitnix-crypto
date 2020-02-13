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

namespace Bitnix\Crypto\Password;

use InvalidArgumentException,
    Bitnix\Crypto\HashingError,
    Bitnix\Crypto\PasswordHasher;

/**
 * @version 0.1.0
 */
final class BcryptHasher implements PasswordHasher {

    /**
     * @var array
     */
    private array $options;

    /**
     * @param int $cost
     * @throws InvalidArgumentException
     */
    public function __construct(int $cost = 10) {
        if ($cost < 4) {
            throw new InvalidArgumentException(\sprintf(
                'Bcrypt hasher cost value must be >= 4, got %d', $cost
            ));
        }
        $this->options = ['cost' => $cost];
    }

    /**
     * @param string $password
     * @return string
     * @throws CryptoFailure
     */
    public function hash(string $password) : string {

        if (($size = \strlen($password)) > 72) {
            throw new HashingError(\sprintf(
                'Bcrypt hasher does not support passwords longer than 72 bytes, got %d',
                    $size
            ));
        }

        if (!$hash = \password_hash($password, \PASSWORD_BCRYPT, $this->options)) {
            throw new HashingError(\sprintf(
                'Bcrypt hasher failed: %s',
                    \error_get_last()['message'] ?? 'unknown reason'
            ));
        }

        return $hash;
    }

    /**
     * @return string
     */
    public function __toString() : string {
        return self::CLASS;
    }
}
