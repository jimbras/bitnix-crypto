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
final class Argon2Hasher implements PasswordHasher {

    const ARGON2I         = 'argon2i';  // PASSWORD_ARGON2I
    const ARGON2ID        = 'argon2id'; // PASSWORD_ARGON2ID

    const MEMORY_COST     = 65536;      // PASSWORD_ARGON2_DEFAULT_MEMORY_COST
    const TIME_COST       = 4;          // PASSWORD_ARGON2_DEFAULT_TIME_COST
    const THREADS         = 1;          // PASSWORD_ARGON2_DEFAULT_THREADS

    const MIN_MEMORY_COST = 8;
    const MIN_THREADS     = 1;

    private const SUPPORTED = [
        self::ARGON2I  => true,
        self::ARGON2ID => true
    ];

    /**
     * @var string
     */
    private string $algo;

    /**
     * @var array
     */
    private array $options;

    /**
     * @param string $algo
     * @param int $memcost
     * @param int $timecost
     * @param int $threads
     * @throws InvalidArgumentException
     */
    public function __construct(
        string $algo  = self::ARGON2I,
        int $memcost  = self::MEMORY_COST,
        int $timecost = self::TIME_COST,
        int $threads  = self::THREADS) {

        if (!isset(self::SUPPORTED[$algo])) {
            throw new InvalidArgumentException(\sprintf(
                'Argon2 hasher doesn\'t support the %s algo, only %s are supported',
                    $algo,
                    \implode(' and ', \array_keys(self::SUPPORTED))
            ));
        }

        $this->algo = $algo;

        $this->options = [
            'memory_cost' => $this->value($memcost, self::MIN_MEMORY_COST, 'memory cost value'),
            'time_cost'   => $timecost, // no minimum
            'threads'     => $this->value($threads, self::MIN_THREADS, 'thread count')
        ];
    }

    /**
     * @param int $value
     * @param int $min
     * @param string $option
     * @return int
     * @throws InvalidArgumentException
     */
    private function value(int $value, int $min, string $option) : int {
        if ($value < $min) {
            throw new InvalidArgumentException(\sprintf(
                '%s %s must be >= %d, got %d',
                    \ucfirst($this->algo),
                    $option,
                    $min,
                    $value
            ));
        }
        return $value;
    }

    /**
     * @param string $password
     * @return string
     * @throws CryptoFailure
     */
    public function hash(string $password) : string {
        if (!$hash = \password_hash($password, $this->algo, $this->options)) {
            throw new HashingError(\sprintf(
                '%s hasher failed: %s',
                    \ucfirst($this->algo),
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
