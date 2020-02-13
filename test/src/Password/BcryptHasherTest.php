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
    ReflectionObject,
    Bitnix\Crypto\HashingError,
    PHPUnit\Framework\TestCase;

/**
 * @version 0.1.0
 */
class BcryptHasherTest extends TestCase {

    public function testConstructorError() {
        $this->expectException(InvalidArgumentException::CLASS);
        new BcryptHasher(3);
    }

    public function testHasherError() {
        $this->expectException(HashingError::CLASS);

        $hasher = new BcryptHasher();
        $object = new ReflectionObject($hasher);
        $opts = $object->getProperty('options');
        $opts->setAccessible(true);
        $opts->setValue($hasher, ['cost' => 1]); // simulate an error

        @$hasher->hash('foo');
    }

    public function testHasherPasswordLengthError() {
        $this->expectException(HashingError::CLASS);
        $hasher = new BcryptHasher();
        $hasher->hash(\str_repeat('x', 73));
    }

    public function testHash() {
        $hasher = new BcryptHasher();
        $password = \str_repeat('x', 72);
        $hash = $hasher->hash($password);
        $this->assertTrue(\password_verify($password, $hash));
    }

    public function testToString() {
        $this->assertIsString((string) new BcryptHasher());
    }
}
