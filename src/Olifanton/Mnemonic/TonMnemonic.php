<?php declare(strict_types=1);

namespace Olifanton\Mnemonic;

use ajf\TypedArrays\Uint8Array;
use Olifanton\Mnemonic\Crypto\Hmac;
use Olifanton\Mnemonic\Crypto\Pbkdf2;
use Olifanton\Mnemonic\Exceptions\TonMnemonicException;
use Olifanton\Mnemonic\Wordlist\Bip39English;
use Olifanton\Utils\Bytes;
use Olifanton\Utils\Crypto;
use Olifanton\Utils\Exceptions\CryptoException;
use Olifanton\Utils\KeyPair;

class TonMnemonic
{
    public const WORDS_COUNT = 24;
    private const PBKDF_ITERATIONS = 100000;

    /**
     * @return string[]
     * @throws TonMnemonicException
     */
    public static function generate(?string $password = null, int $wordsCount = self::WORDS_COUNT): array
    {
        $c = 0;

        while (true) {
            $c++;
            $mnemonicArray = [];
            $rnd = self::getRandomValues($wordsCount);

            for ($i = 0; $i < $wordsCount; $i++) {
                $mnemonicArray[] = Bip39English::WORDS[$rnd[$i] & 2047];
            }

            if ($password && strlen($password) > 0) {
                if (!self::isPasswordNeeded($mnemonicArray)) {
                    continue;
                }
            }

            if (!self::isBasicSeed(self::mnemonicToEntropy($mnemonicArray, $password))) {
                continue;
            }

            break;
        }

        return $mnemonicArray;
    }

    /**
     * @param string[] $mnemonicArray
     * @param string[] $wordlist
     * @throws TonMnemonicException
     */
    public static function validate(array $mnemonicArray, ?string $password = null, array $wordlist = Bip39English::WORDS): bool
    {
        foreach ($mnemonicArray as $word) {
            if (!in_array($word, $wordlist, true)) {
                return false;
            }
        }

        if ($password && strlen($password) > 0) {
            if (!self::isPasswordNeeded($mnemonicArray)) {
                return false;
            }
        }

        return self::isBasicSeed(self::mnemonicToEntropy($mnemonicArray, $password));
    }

    /**
     * @param string[] $mnemonicArray
     * @throws TonMnemonicException
     */
    public static function isPasswordNeeded(array $mnemonicArray): bool
    {
        $entropy = self::mnemonicToEntropy($mnemonicArray, '');

        return self::isPasswordSeed($entropy) && !self::isBasicSeed($entropy);
    }

    /**
     * @param string[] $mnemonicArray
     * @throws TonMnemonicException
     */
    public static function mnemonicToSeed(array $mnemonicArray, ?string $password = ''): Uint8Array
    {
        $entropy = self::mnemonicToEntropy($mnemonicArray, $password);
        $seed = Pbkdf2::pbkdf2Sha512($entropy, 'TON default seed', self::PBKDF_ITERATIONS);

        return Bytes::arraySlice($seed, 0, 32);
    }

    /**
     * @param string[] $mnemonicArray
     * @throws TonMnemonicException
     */
    public static function mnemonicToKeyPair(array $mnemonicArray, ?string $password = null): KeyPair
    {
        try {
            return Crypto::keyPairFromSeed(self::mnemonicToSeed($mnemonicArray, $password));
        } catch (CryptoException $e) {
            throw new TonMnemonicException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * @throws TonMnemonicException
     */
    public static function isPasswordSeed(Uint8Array $entropy): bool
    {
        $seed = Pbkdf2::pbkdf2Sha512($entropy, 'TON fast seed version', 1);

        return $seed[0] == 1;
    }

    /**
     * @throws TonMnemonicException
     */
    private static function isBasicSeed(Uint8Array $entropy): bool
    {
        $seed = Pbkdf2::pbkdf2Sha512($entropy, 'TON seed version', max(1, (int)floor(self::PBKDF_ITERATIONS / 256)));

        return $seed[0] == 0;
    }

    /**
     * @throws TonMnemonicException
     */
    private static function mnemonicToEntropy(array $mnemonicArray, ?string $password = ''): Uint8Array
    {
        if ($password === null) {
            $password = '';
        }

        $mnemonicPhrase = implode(" ", $mnemonicArray);

        return Hmac::hmacSha512($mnemonicPhrase, $password);
    }

    /**
     * @return int[]
     * @throws TonMnemonicException
     */
    private static function getRandomValues(int $count): array
    {
        $result = [];

        try {
            for ($i = 0; $i < $count; $i++) {
                $result[] = random_int(0, PHP_INT_MAX - 1);
            }

            return $result;
        } catch (\Throwable $e) {
            throw new TonMnemonicException($e->getMessage(), $e->getCode(), $e);
        }
    }
}
