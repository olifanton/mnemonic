<?php declare(strict_types=1);

namespace Olifanton\Mnemonic;

use Olifanton\TypedArrays\Uint8Array;
use Olifanton\Mnemonic\Crypto\Hmac;
use Olifanton\Mnemonic\Crypto\Pbkdf2;
use Olifanton\Mnemonic\Exceptions\TonMnemonicException;
use Olifanton\Mnemonic\Wordlist\Bip39English;
use Olifanton\Interop\Bytes;
use Olifanton\Interop\Crypto;
use Olifanton\Interop\Exceptions\CryptoException;
use Olifanton\Interop\KeyPair;

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
        $maxRandomValue = count(Bip39English::WORDS) - 1;
        $isPassword = $password && $password !== '';

        while (true) {
            $mnemonicArray = [];
            $rnd = self::getRandomValues($wordsCount, 0, $maxRandomValue);

            for ($i = 0; $i < $wordsCount; $i++) {
                $mnemonicArray[] = Bip39English::WORDS[$rnd[$i]];
            }

            if ($isPassword && !self::isPasswordNeeded($mnemonicArray)) {
                continue;
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

        if ($password && $password !== "" && !self::isPasswordNeeded($mnemonicArray)) {
            return false;
        }

        return self::isBasicSeed(self::mnemonicToEntropy($mnemonicArray, $password));
    }

    /**
     * @param string[] $mnemonicArray
     * @throws TonMnemonicException
     */
    public static function isPasswordNeeded(array $mnemonicArray): bool
    {
        $entropy = self::mnemonicToEntropy($mnemonicArray, "");

        return self::isPasswordSeed($entropy) && !self::isBasicSeed($entropy);
    }

    /**
     * @param string[] $mnemonicArray
     * @throws TonMnemonicException
     */
    public static function mnemonicToSeed(array $mnemonicArray, ?string $password = ""): Uint8Array
    {
        if (!self::validate($mnemonicArray, empty($password) ? null : $password)) {
            throw new TonMnemonicException("Invalid mnemonic phrase");
        }

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

        return $seed[0] === 1;
    }

    /**
     * @throws TonMnemonicException
     */
    private static function isBasicSeed(Uint8Array $entropy): bool
    {
        $seed = Pbkdf2::pbkdf2Sha512($entropy, 'TON seed version', max(1, (int)floor(self::PBKDF_ITERATIONS / 256)));

        return $seed[0] === 0;
    }

    /**
     * @param string[] $mnemonicArray
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
    private static function getRandomValues(int $count, int $minValue, int $maxValue): array
    {
        $result = [];

        try {
            for ($i = 0; $i < $count; $i++) {
                do {
                    $value = random_int($minValue, $maxValue);
                } while (in_array($value, $result, true));

                $result[] = $value;
            }

            return $result;
        } catch (\Throwable $e) {
            throw new TonMnemonicException($e->getMessage(), $e->getCode(), $e);
        }
    }
}
