<?php declare(strict_types=1);

namespace Olifanton\Mnemonic\Tests\Crypto;

use Olifanton\Mnemonic\Crypto\Hmac;
use Olifanton\Utils\Bytes;
use PHPUnit\Framework\TestCase;

class HmacTest extends TestCase
{
    /**
     * @throws \Olifanton\Mnemonic\Exceptions\TonMnemonicException
     */
    public function testHmacSha512(): void
    {
        $cases = [
            ['mustafa', 'carrot', '651df9349efe6bd60e33ab842eed03ca5816e0248982af6cfb42db5af28beb204524cf96e33d405cecb3c9e05a6ebf23635bc32591b828bd26e673995d511d06'],
            ['zoomer', 'witcher', 'fda354547a606955c37e3295deecde67c61b953200cbd8e13d0df766905664508c71ef47d94a21c39fa88ecec12770ac33e95aa9ddd45b2deed87b6a7e848296'],
            ['1', '', '70cf5c654a3335e493c263498b849b1aa425012914f8b5e77f4b7b7408ad207db9758f7c431887aa8f4885097e3bc032ee78238157c2ad43e900b69c60aee71e'],
            ['kek', 'kek', '4a552edb36a8bc4f82d9342a7b4044185a5354eaccbce81b6b0ce6ac84e621e4310ca6cf817ea0af0a4f239585bf8f97955ab7122b7add9b030e5caf0832f1c0'],
            ['kek', '', '0ecf0776e9d387590faba221714b21973b09d431bd5e5ddc7b50242c1c6355df4cf93950444cc637d3ce97b859db35ed0e02b08c4fb8db0ba8412761e6df0e31'],
        ];

        foreach ($cases as $case) {
            [$phrase, $password, $expected] = $case;

            $this->assertEquals(
                $expected,
                Bytes::bytesToHexString(
                    Hmac::hmacSha512($phrase, $password),
                )
            );
        }
    }
}
