<?php declare(strict_types=1);

namespace Olifanton\Mnemonic\Crypto;

use Olifanton\TypedArrays\Uint8Array;
use Olifanton\Mnemonic\Exceptions\TonMnemonicException;
use Olifanton\Interop\Bytes;

final class Hmac
{
    /**
     * @throws TonMnemonicException
     */
    public static function hmacSha512(string $phrase, string $password): Uint8Array
    {
        try {
            $result = hash_hmac(
                'sha512',
                $password,
                $phrase,
                true,
            );

            return Bytes::bytesToArray($result);
        } catch (\Throwable $e) {
            throw new TonMnemonicException("hash_hmac error: " . $e->getMessage(), $e->getCode(), $e);
        }
    }
}
