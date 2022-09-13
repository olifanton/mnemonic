<?php declare(strict_types=1);

namespace Olifanton\Mnemonic\Tests;

use Olifanton\Mnemonic\Exceptions\TonMnemonicException;
use Olifanton\Mnemonic\TonMnemonic;
use Olifanton\Mnemonic\Wordlist\Bip39English;
use Olifanton\Utils\Bytes;
use PHPUnit\Framework\TestCase;

class TonMnemonicTest extends TestCase
{
    private const STUB_MNEMONIC = [
        'bring',  'like',    'escape',
        'health', 'chimney', 'pear',
        'whale',  'peasant', 'drum',
        'beach',  'mass',    'garden',
        'riot',   'alien',   'possible',
        'bus',    'shove',   'unable',
        'jar',    'anxiety', 'click',
        'salon',  'canoe',   'lion',
    ];

    private const STUB_PASSWORD_MNEMONIC = [
        'minimum', 'candy',   'praise',
        'dolphin', 'doll',    'arrest',
        'duty',    'pill',    'bronze',
        'embrace', 'execute', 'midnight',
        'trial',   'pink',    'guitar',
        'cake',    'sail',    'color',
        'field',   'used',    'art',
        'method',  'fashion', 'supply',
    ];

    private const STUB_PASSWORD = 'foobar';

    /**
     * @throws TonMnemonicException
     */
    public function testGenerate(): void
    {
        $mnemonic = TonMnemonic::generate();
        $this->assertCount(TonMnemonic::WORDS_COUNT, $mnemonic);
        $this->assertTrue(TonMnemonic::validate($mnemonic));
        $this->assertFalse(TonMnemonic::validate($mnemonic, 'barbaz'));
        $this->assertFalse(TonMnemonic::isPasswordNeeded($mnemonic));
    }

    /**
     * @throws TonMnemonicException
     */
    public function testGenerateWithPassword(): void
    {
        $randWord = Bip39English::WORDS[array_rand(Bip39English::WORDS)];
        $mnemonic = TonMnemonic::generate($randWord);
        $this->assertCount(TonMnemonic::WORDS_COUNT, $mnemonic);
        $this->assertFalse(TonMnemonic::validate($mnemonic));
        $this->assertTrue(TonMnemonic::validate($mnemonic, $randWord));
        $this->assertTrue(TonMnemonic::isPasswordNeeded($mnemonic));
    }

    /**
     * @throws TonMnemonicException
     */
    public function testValidate(): void
    {
        $this->assertTrue(TonMnemonic::validate(self::STUB_MNEMONIC));
        $this->assertFalse(TonMnemonic::validate(self::STUB_PASSWORD_MNEMONIC));
        $this->assertTrue(TonMnemonic::validate(self::STUB_PASSWORD_MNEMONIC, self::STUB_PASSWORD));
    }

    /**
     * @throws TonMnemonicException
     */
    public function testIsPasswordNeeded()
    {
        $this->assertFalse(TonMnemonic::isPasswordNeeded(self::STUB_MNEMONIC));
        $this->assertTrue(TonMnemonic::isPasswordNeeded(self::STUB_PASSWORD_MNEMONIC));
    }

    /**
     * @throws TonMnemonicException
     */
    public function testMnemonicToSeed(): void
    {
        $basicSeedReferenceStub = '5844f115d314ff833331ee02bbfea358b5a0c1521c65e70f8c29cbde9f38b5c3';
        $withPasswordSeedReferenceStub = '2299becdd2c577f38f5c3ceda4577920968c8e41571e64547c018a64edc2131e';

        $this->assertEquals($basicSeedReferenceStub, Bytes::bytesToHexString(TonMnemonic::mnemonicToSeed(self::STUB_MNEMONIC)));
        $this->assertEquals($withPasswordSeedReferenceStub, Bytes::bytesToHexString(TonMnemonic::mnemonicToSeed(self::STUB_PASSWORD_MNEMONIC, self::STUB_PASSWORD)));
    }

    /**
     * @throws TonMnemonicException
     */
    public function testMnemonicToKeyPair(): void
    {
        $publicKeyReferenceStub = 'ef117f300d4eca0f88ffd17d00340dee0c864b0d8300197203143c036af3be29';
        $secretKeyReferenceStub = '5844f115d314ff833331ee02bbfea358b5a0c1521c65e70f8c29cbde9f38b5c3ef117f300d4eca0f88ffd17d00340dee0c864b0d8300197203143c036af3be29';

        $keyPair = TonMnemonic::mnemonicToKeyPair(self::STUB_MNEMONIC);

        $this->assertEquals($publicKeyReferenceStub, Bytes::bytesToHexString($keyPair->publicKey));
        $this->assertEquals($secretKeyReferenceStub, Bytes::bytesToHexString($keyPair->secretKey));
    }

    /**
     * @throws TonMnemonicException
     */
    public function testMnemonicToKeyPairPassword(): void
    {
        $publicKeyReferenceStub = '2906a33e8edb1ee2a0b9974a817113914b4996796f2af12b7c20712a974e9638';
        $secretKeyReferenceStub = '2299becdd2c577f38f5c3ceda4577920968c8e41571e64547c018a64edc2131e2906a33e8edb1ee2a0b9974a817113914b4996796f2af12b7c20712a974e9638';

        $keyPair = TonMnemonic::mnemonicToKeyPair(self::STUB_PASSWORD_MNEMONIC, self::STUB_PASSWORD);

        $this->assertEquals($publicKeyReferenceStub, Bytes::bytesToHexString($keyPair->publicKey));
        $this->assertEquals($secretKeyReferenceStub, Bytes::bytesToHexString($keyPair->secretKey));
    }
}
