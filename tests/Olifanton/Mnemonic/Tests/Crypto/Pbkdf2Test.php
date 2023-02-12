<?php declare(strict_types=1);

namespace Olifanton\Mnemonic\Tests\Crypto;

use Olifanton\Mnemonic\Crypto\Pbkdf2;
use Olifanton\Interop\Bytes;
use PHPUnit\Framework\TestCase;

class Pbkdf2Test extends TestCase
{
    /**
     * @throws \Olifanton\Mnemonic\Exceptions\TonMnemonicException
     */
    public function testPbkdf2Sha512(): void
    {
        $cases = [
            ['tutturu', 'blabla', 10, '3817ff5ce29ec89db7a591b3ec8b053088731a7c967665b6dac9203bc1d75674800a2846c17b6e417269d787cff0b5c23aba5aab6e76ffde441633db1f2bf87b'],
            ['gizmodo_lopez', 'hashimoto', 1000, '308f90aab4434b62e13ff593b5472ee8ae3672e82fe08dfe48a0a6625a9d20304134186cf9889c8b8f135a0f9d5392ed0875fcd1e50c53d54b72dc3001f48377'],
        ];

        foreach ($cases as $case) {
            [$key, $salt, $iterations, $expected] = $case;
            $this->assertEquals(
                $expected,
                Bytes::bytesToHexString(Pbkdf2::pbkdf2Sha512(
                    Bytes::stringToBytes($key),
                    $salt,
                    $iterations,
                )),
            );
        }
    }
}
