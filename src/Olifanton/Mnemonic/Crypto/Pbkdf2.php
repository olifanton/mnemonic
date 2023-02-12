<?php declare(strict_types=1);

namespace Olifanton\Mnemonic\Crypto;

use Olifanton\TypedArrays\Uint8Array;
use Olifanton\Mnemonic\Exceptions\TonMnemonicException;
use Olifanton\Interop\Bytes;

final class Pbkdf2
{
    /**
     * @throws TonMnemonicException
     */
    public static function pbkdf2Sha512(Uint8Array $key, string $salt, int $iterations): Uint8Array
    {
        try {
            $result = hash_pbkdf2(
                'sha512',
                Bytes::arrayToBytes($key),
                $salt,
                $iterations,
                64,
                true,
            );

            return Bytes::bytesToArray($result);
        } catch (\Throwable $e) {
            throw new TonMnemonicException("hash_pbkdf2 error: " . $e->getMessage(), $e->getCode(), $e);
        }
    }
}
