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
    ReflectionObject,
    Bitnix\Crypto\EncryptionError,
    Bitnix\Crypto\DecryptionError,
    PHPUnit\Framework\TestCase;

/**
 * @version 0.1.0
 */
class OpenSslEncrypterTest extends TestCase {

    public function testUnsupportedAlgo() {
        $this->expectException(InvalidArgumentException::CLASS);
        new OpenSslEncrypter('whatever', 'FOO');
    }

    public function testEngine() {
        $encrypter = new OpenSslEncrypter('some secret key');

        $input = 'some secret data';
        $password = 'some secret password';

        $output = $encrypter->encrypt($input, $password);
        $raw = $encrypter->encrypt($input, $password, false);
        $this->assertNotEquals($input, $output);
        $this->assertNotEquals($raw, $output);

        $decrypted = $encrypter->decrypt($output, $password);
        $this->assertEquals($input, $decrypted);

        $decrypted = $encrypter->decrypt($raw, $password, false);
        $this->assertEquals($input, $decrypted);
    }

    public function testEncryptionError() {
        $this->expectException(EncryptionError::CLASS);
        $encrypter = new OpenSslEncrypter('some secret key');
        $object = new ReflectionObject($encrypter);
        $property = $object->getProperty('ivlen');
        $property->setAccessible(true);
        $property->setValue($encrypter, 0);
        $encrypter->encrypt('foo', 'bar');
    }

    public function testDecryptionError() {
        $this->expectException(DecryptionError::CLASS);

        $encrypter = new OpenSslEncrypter('some secret key');

        $input = 'some secret data';
        $password = 'some secret password';
        $output = $encrypter->encrypt($input, $password);

        $encrypter->decrypt($output, 'wrong password');
    }

    public function testDecryptionHashError() {
        $this->expectException(DecryptionError::CLASS);

        $encrypter = new OpenSslEncrypter('some secret key');

        $input = 'some secret data';
        $password = 'some secret password';

        $output = $encrypter->encrypt($input, $password);
        $output = 'x' . \substr($output, 1);

        $encrypter->decrypt($output, $password);
    }

    public function testToString() {
        $this->assertIsString((string) new OpenSslEncrypter('whatever'));
    }
}
