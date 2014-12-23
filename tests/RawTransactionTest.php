<?php

use BitWasp\BitcoinLib\BitcoinLib;
use BitWasp\BitcoinLib\RawTransaction as RawTransaction;

require_once(__DIR__. '/../vendor/autoload.php');

class RawTransactionTest extends PHPUnit_Framework_TestCase
{
    public $testHexEncode_i;

    public function __construct() {
    }

    public function setup() {
        BitcoinLib::setMagicByteDefaults('bitcoin');
        RawTransaction::$VERBOSE = true;
    }

    public function tearDown() {
    }

    public function testDecodeRedeemScript() {
        // Random samples from txs in the blockchain
        $samples = [
            "5221032c6aa78662cc43a3bb0f8f850d0c45e18d0a49c61ec69db87e072c88d7a9b6e9210353581fd2fc745d17264af8cb8cd507d82c9658962567218965e750590e41c41e21024fe45dd4749347d281fd5348f56e883ee3a00903af899301ac47ba90f904854f53ae",
"5141048ff228400b3056084121fa83658c43858e3826d59ddc6cfd033df80565f8cc96e09e26e6a2320958a999cb82030d781698176a591424cf4f66b5644e7c8e690a41040f63d3a4b5d797b8ceb443ae54a45b7bb0465a792844e104e31eda18f8a0b0b8f42adaac0002bac7aae6a5cd4106be45172463e9caf44aa567da486455063d1152ae",
"524104664547a29ffc51db8d46377c1c6611914e11a9c36a83992e642b6c3aa1f0017eee1d77d6d0e4f3b82be92067b39d7f62fe2da7b680e3e306402bf53f8dd5ef04410496cb89ca7f8f244808b4a50ee80e9acd12f801d33646aa9a50eb4a6b550f6520b4204a79f0192a30fc8c7b0eef18d49b3b720373f6b2b928023ae4b463c2c4eb52ae",
"522102c33586c016c66158f921c54e30628d682627839d0297f800050b981ab298b58a2102bd4d0115f28b4ac3122e89ebab628f1de2db0a3947721f2fe9b17f9b96e2204052ae",
"524104192944fe1ecf2bb78174a282a3b7d3a457bb40993a6785853cfcedf5bb6f67fd453db59b4e2cfd864480c86d816b383b0be51f82444f7bca0cdaa12e002b25da4104738bcb941b0ca59dad113393c212be91b4bb648efce44567bd372ffac64c6f373d2d928a34c6d1d98fced6a6b03852fc592eef7534d23b801a714e11f1a061ac410491ccd85240d31e84e40586d0bf10a1f1e9d309bffac8e179534be2a28310e92c486d9c7e47ee76e23f6b6f390075e16cf08b6ce9c3d2383c5a3a20b6598d224e53ae",
"52410453e1bb5aa30c3711ac64ca03a38d7f248db3b31a2559efa8a4cb6fa63b5356e9d2cb8c26b722d7f984cc51ba6bfceb2e5306249f6ba626e73de1d412f2e8d4594104be2c03fe4f9aa55dea54812822a563138b4c12651ce3d1161b246c47379838ae1f7a0df55e6b475c2cddd278bcd130898a21e319e1bc02da86876efb9fcb621c4104cf5189fa8b6457a5e06f652ef8666499574632bc5c75f51fb049dcc93638309f493594e4bd6b1d6ac92f6d77cc52db255b92f20749b237927fb2a60d7c887a1053ae",
"5241048c1bbabfd38a9d462443e9bd99e133f512efa9548743ffb3f544dcc83b9b0356780796678519987ba04a054445e0cea2a60f1cafc1dbcc97c412338771b094374104bf5d3c29bad79db8f541b0d1095ef1f8ba4e8eda75936dcec81ac72599121b561f2b4ce9a2947cf0a5498888ee8e2a918c7e595da8fa1ae5b28df607e5fc29bb4104d79d37c0f322442bea954bb3fda3a97b24b113152a638316a1fbd44673e28967cefca7c3ed366ed41bbc0978dc308efab89f6e9010912d1e6c3fed0d4dc2b63d53ae",
"5121031b9abc9a11a4a078509969f12de3129bf81060b001742e05cd8041a7e7402bcb51ae",
"5241043a0f00454bdcd92698bebd22de0785c8dd190144115b3eced47f26796e24c3050faa3cb3b46a5a868a8f77f7f08ddda7c90952ca07bc18fc9765b8f0bc28cdd941044d7e454064678f032c6a845a986a41e20ae224a7843eb397637e7d1df2c80762b0a14d348cb2a4261cf83fba77d1e025a9eaaf251e1a23f9caabb4c9c5fba5314104ba5b7a9ce88ee36d8689e6a70e847b88d2ddcd12a008195f5b841f88485e14d6a3abc4120e721a50655ce3ba63606ba7ac927254f89ec3d0dea3bfe1d7b2797653ae",
"5241046bcd91262b52419bdb0a88cc628e6eeed8ca7c60857a04be80c9cef320a775881d01b439cefc6e814f713c753be596fb65b5575f9e99583cd50776474e80adc14104b730f446201772dbc67d39f72fe9ef2e966066718070a4248874fb237a325dfa43073a893f95ae713d40194bac5d6cb23d25616e0966286c9c7416afe7214ac84104b31a45c0362e0c56e868bb7563334b3b35eb0f4af810648e45e365c46eaf983a155b6ec834db5143a7df47780fbf7e9f6ac5c3d45837b6c76b0c9c4c864feee453ae",
"524104f10d42e5a5dc24dabe524dc305f9deab2c5b58c42aa83833d1d2ad38c9b796b4756a99e60bfee19e92424f3aa919fb63377b6d8d35d091d6a5de62b58b8c8d7721025563ee4b549f5a7d3dfb046a088815c69ebd44b389a78342ccb01e77d89465a752ae",
"522102c48bf0c25bf78fbe98988ef8f27ee05284f79c550e987a88e1237872c030ab8021026f6020210361586f02c93cfb926fed3d240b7f11b1a5694b36c826561abd3932210352057bbf5c024edd3630606689956c52104150d1c494b1d92ca6c7243d5eeb7453ae",
"522102d7297e56bc410c2d1671cd2694686400f59061bef1bbb6f7e3269dacbbdce53e2102421a4efafabd2534116deb6c00a01831de71c62c53a5e718b852ccd81a7ff98c52ae",
"522102d7297e56bc410c2d1671cd2694686400f59061bef1bbb6f7e3269dacbbdce53e2102421a4efafabd2534116deb6c00a01831de71c62c53a5e718b852ccd81a7ff98c52ae",
"52210374763369da3dca422b64e13ae1cf81a5f68dd09a1efcd463b5511fe7a436207a21021d7e25870057383faad795f651b3f5844c4d3ebb1e3a31e444e6a21d9af371642102c5463df6e77f7f659d123ca19e079ef9ec08e1ddfa4a1bcb4814902b2b1ad41c53ae",
"5241046dae34916bec595e73b3fabfd1aad2158994fee1a5bc19216654dc49b47f1976a26d7a6d3c7b713f8650121812253a206c4cd7f1e7b453e8e700c720e99c60564104fcb3a8fd045eb2c77a45fdfed73317c22b4ab40de5950c944ff8b1cf45eb83aaafc8d987fe1706d10febc6277223569e0df10881b8cea2435b4fa3bdabf41ad021036c06d0a475646980d4ede31b6b4864946fe7fb54fa15102b03ac16a56c4300f053ae",
"524104d403a9ec23cb289734645337a079c636ecc47b6015ebd88e972741948ddd65a708f8238f1da4b8f70945ae57288a4bc406e3811a0b83b4e610565cc83a5faff741046c82c6671ada6c430d8ea81b27ecae04fa9f0b4ab14bcceb89c589ea0d7b1919565221ef6c2004a6204f1d6d616eb770c13dbda3cdf271f2ae6fe5a654b5a42e2102e3929380fccb603649a8dd775ec2b1e81748b2749503e039530330f1a5b448bf53ae",
"5221039bf1c1ec550815dee677d1b391a03f5f501abe6fd9817b2486bc03aa7ae038d8410437d0fd54cbbe8d4e6bd12d19b1c863d3cfbce71c4b31541546685c090d9572a2d2f5f30c58d45c7141cf29b7fe83002f29abccc9c290b7dba6eed9e9d773d1bc2102521e92a6b26db346cb8e2a27ceb2ec83905f3f8d3f8d52634c82c3ad8d0f188a53ae"
        ];

        foreach($samples as $sample) {
            $raw = RawTransaction::decode_redeem_script($sample);
            $this->assertTrue( is_array($raw) );
        }
    }

    /**
     * !! TESTNET !!
     *
     */
    public function testSignP2SH() {
        BitcoinLib::setMagicByteDefaults('bitcoin-testnet');

        // 1 loop takes ~2.5s
        $cnt = (getenv('BITCOINLIB_EXTENSIVE_TESTING') ?: 1) * 1;

        $redeem_script = "522103c0b1fd07752ebdd43c75c0a60d67958eeac8d4f5245884477eae094c4361418d2102ab1fae8dacd465460ad8e0c08cb9c25871782aa539a58b65f9bf1264c355d0982102dc43b58ee5313d1969b939718d2c8104a3365d45f12f91753bfc950d16d3e82e53ae";

        $inputs = array(
            array(
                "txid" => "83c5c88e94d9c518f314e30ca0529ab3f8e5e4f14a8936db4a32070005e3b61f",
                "vout" => 0,
                "scriptPubKey" => "a9145fe34588f475c5251ff994eafb691a5ce197d18b87",

                // only needed for RawTransaction::sign
                "redeemScript" => $redeem_script,

                // only for debugging
                "value" => 0.00010000
            )
        );
        $outputs = array(
            "n3P94USXs7LzfF4BKJVyGv2uCfBQRbvMZJ" => 0.00010000
        );
        $raw_transaction = RawTransaction::create($inputs, $outputs);

        // create first wallet
        $wallet1 = array();
        RawTransaction::private_keys_to_wallet($wallet1, array("cV2BRcdtWoZMSovYCpoY9gyvjiVK5xufpAwdAFk1jdonhGZq1cCm"));
        RawTransaction::redeem_scripts_to_wallet($wallet1, array($redeem_script));

        // create second wallet
        $wallet2 = array();
        RawTransaction::private_keys_to_wallet($wallet2, array("cMps8Dg4Z1ThcwvPiPpshR6cbosYoTrgUwgLcFasBSxsdLHwzoUK"));
        RawTransaction::redeem_scripts_to_wallet($wallet2, array($redeem_script));

        // create third wallet
        $wallet3 = array();
        RawTransaction::private_keys_to_wallet($wallet3, array("cNn72iUvQhuzZCWg3TC31fvyNDYttL8emHgMcFJzhF4xnFo8LYCk"));
        RawTransaction::redeem_scripts_to_wallet($wallet3, array($redeem_script));

        for ($i = 0; $i < $cnt; $i++) {
            // sign with first key
            $sign = RawTransaction::sign($wallet1, $raw_transaction, json_encode($inputs));
            $this->assertEquals(2, $sign['req_sigs']);
            $this->assertEquals(1, $sign['sign_count']);
            $this->assertEquals('false', $sign['complete']);

            // sign with second key
            $sign = RawTransaction::sign($wallet2, $sign['hex'], json_encode($inputs));
            $this->assertEquals(2, $sign['req_sigs']);
            $this->assertEquals(2, $sign['sign_count']);
            $this->assertEquals('true', $sign['complete']);

            // sign with third key
            $sign = RawTransaction::sign($wallet3, $sign['hex'], json_encode($inputs));
            $this->assertEquals(2, $sign['req_sigs']);
            $this->assertEquals(3, $sign['sign_count']);
            $this->assertEquals('true', $sign['complete']);

            $this->assertTrue(RawTransaction::validate_signed_transaction($sign['hex'], json_encode($inputs)));
        }
    }

    public function testCreateRaw() {
        $data = [
            1 => [
                'inputs' => [
                    [
                        "txid" => "5a373fd13679fc55f479f08bef25d5e808031f97331a48f950ced89d7e99c269",
                        "vout" => 31,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "29b509aa81cb4115645b536c14e6c0f7699f5e2228d95c79300f23004aae9aab",
                        "vout" => 123,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "e59686315e67427c465d6febe77ce1b93af66f1e25590353743fa95a4c1836c0",
                        "vout" => 1,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "00078ef8003e86b1ec57a69842e4a64e54d7dea9dddfb4124f257cb3bf077172",
                        "vout" => 17,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "fe4d7c39fdc034b8c5497a0ff07c17ea68bc02734f5247a5db616a12002086fb",
                        "vout" => 57,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "8acd7cc80178a00404dfa9061a0028d74239a4bddebf54eacd0fcf657cb535db",
                        "vout" => 9,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "2d3631bc56b34e845bfbf90bb30b473601a5dd03ffbadb92db98ab4de1f89f53",
                        "vout" => 31,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "d79ef324ffdeacbad1d8f02ec9dd3707277f1ec1365a2f0e8fa5d027bfab0dbc",
                        "vout" => 17,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ]
                ],
                'outputs' => [
                    "15XjXdS1qTBy3i8vCCriWSAbm1qx5JgJVz" => 0.14750000,
                    "1L6hCPsCq7C5rNzq7wSyu4eaQCq8LeipmG" => 0.01373172
                ]
            ]
        ];

        foreach($data as $test) {
            $create = RawTransaction::create($test['inputs'], $test['outputs'], '00');
            $this->assertTrue(is_string($create));
        }
    }

    public function testSign()
    {
        BitcoinLib::setMagicByteDefaults('bitcoin');

        // 1 loop takes ~0.22s
        $cnt = (getenv('BITCOINLIB_EXTENSIVE_TESTING') ?: 1) * 5;

        $inputs = array(
            array(
                'txid' => '6737e1355be0566c583eecd48bf8a5e1fcdf2d9f51cc7be82d4393ac9555611c',
                'vout' => 0
            )
        );

        $outputs = array('1PGa6cMAzzrBpTtfvQTzX5PmUxsDiFzKyW' => "0.00015");

        $json_inputs = json_encode(
            array(
                array(
                    'txid' => '6737e1355be0566c583eecd48bf8a5e1fcdf2d9f51cc7be82d4393ac9555611c',
                    'vout' => 0,
                    // OP_DUP OP_HASH160 push14bytes       PkHash      OP_EQUALVERIFY OP_CHECKSIG
                    'scriptPubKey' => '76a914' . '7e3f939e8ded8c0d93695310d6d481ae5da39616' . '88ac'
                )
            )
        );

        $wallet = array();
        RawTransaction::private_keys_to_wallet($wallet, array('L2V4QgXVUyWVoMGejTj7PrRUUCEi9D9Y1AhUM8E6f5yJm7gemgN6'), '00');

        $raw_transaction = RawTransaction::create($inputs, $outputs);

        for ($i = 0; $i < $cnt; $i++) {
            $sign = RawTransaction::sign($wallet, $raw_transaction, $json_inputs);
            $this->assertTrue(RawTransaction::validate_signed_transaction($sign['hex'], $json_inputs));
        }
    }

    public function testPayToScriptHashSignedTransaction() {
        $data = [
        0 => [
            'tx' => '01000000012228bfe4d2ddd0818d39a81c9e0d41472790eab9c7409749c3b4c65061e1956300000000fd1e0100483045022100900883802edd7db97447182f69c49bc04c7eacc977bed53bc15e9ba648799fde02205146c913b5cdd8ebe03b9babde8631184ac8b6d7735ba8c2ac8da96d891632f601483045022100d57786b2b5f5cdf9211d355f75b87e3049ed9b4bd8ecd95cbb12c76f06bd5fc9022059dbbe08fc8d203fe54acef7163e53d59e8ffd1b4e202d7a53612114d9521897014c89522103386ad259758077336d6301323a8c1ee61ebf819e272e52353a0af76f2d495aee21022d1f8dde5155dee03cf8586f57d06df9100455c6942d7e1fec8892a2499e5a474104fc97d46d5c117eb3c631af52dade567d6ecce84935f3f0ce5df869fe120760f2ee4ecdec9f9efccbe05fb1debca6da055198cfe8adab8795e271916edae9ebc253aeffffffff02d8270000000000001976a9148dde681a2482740d5022bfd61a00c5c9ecc6b7fe88ac584d0000000000001976a9146c2bab1726f4582fbdfb4cd31549b05679cd97c688ac00000000',
            'inputs' => [
                [
                    "txid" => "6395e16150c6b4c3499740c7b9ea902747410d9e1ca8398d81d0ddd2e4bf2822",
                    "vout" => 0,
                    "scriptPubKey" => "a914a1e64962519b43be719392eab45eed5cf1198f4087",
                    "redeemScript" => "522103386ad259758077336d6301323a8c1ee61ebf819e272e52353a0af76f2d495aee21022d1f8dde5155dee03cf8586f57d06df9100455c6942d7e1fec8892a2499e5a474104fc97d46d5c117eb3c631af52dade567d6ecce84935f3f0ce5df869fe120760f2ee4ecdec9f9efccbe05fb1debca6da055198cfe8adab8795e271916edae9ebc253ae"
                ]
            ],
            'outputs' => [
                "3GT4b2TDowpMnvn5xSpPhxCGvFfgNg3gfo" => 0.00040000,
                "1PtY9BWxhGJRM3G4J1bQUXABNUhUsecdpE" => 0.05040048
            ]
        ]];


        foreach($data as $test) {
            $this->assertTrue(RawTransaction::validate_signed_transaction($test['tx'], json_encode($test['inputs']),'00'));
        }
    }

    public function testPayToPubKeyHashSignedTransaction() {
        $data = [
            1 => [
                // Tx : c58ebf5e342191dc9a1797b308ea5c707aa8ea762543184931246b48689a2761
                'tx' => '010000000869c2997e9dd8ce50f9481a33971f0308e8d525ef8bf079f455fc7936d13f375a1f0000008a47304402202de0d834112506ed10549f751ce142094243390f3e035444f105b4764056314302205dfddc421b377c8b089182ddb3928ce02e73c86e5dfb9e66ca6a98810d7a2ac5014104b3d8c8c5896b0ed9537ccbdcfdf3f05cd4299988c72d078b841e0491bab198702c4befaa3da367c117c7c6217cd478c54b572e13de6ddd22c948f4b66c1562b5ffffffffab9aae4a00230f30795cd928225e9f69f7c0e6146c535b641541cb81aa09b5297b0000008a47304402205604456b1ed6dcae5e5f370568dd71c8bfb44823d583e3fa781ae8117ed831a30220154ee1c49bfca8bd1970953255498cb6bc347de1df267ed1b0f70385bca29184014104b3d8c8c5896b0ed9537ccbdcfdf3f05cd4299988c72d078b841e0491bab198702c4befaa3da367c117c7c6217cd478c54b572e13de6ddd22c948f4b66c1562b5ffffffffc036184c5aa93f74530359251e6ff63ab9e17ce7eb6f5d467c42675e318696e5010000008a47304402206c756a38757443794196d16e887c95b9b769b11c608b425e7580e4fcd8456642022040613fbff5e5412c8aa0c3a91b651a6fe6fcf793596a5e29bbc7bc5d73fc683a014104b3d8c8c5896b0ed9537ccbdcfdf3f05cd4299988c72d078b841e0491bab198702c4befaa3da367c117c7c6217cd478c54b572e13de6ddd22c948f4b66c1562b5ffffffff727107bfb37c254f12b4dfdda9ded7544ea6e44298a657ecb1863e00f88e0700110000008c493046022100c24b9c50820d19457fc5842a124500bf2371397144fc6166bdaa4a94275e9dda022100fc6c59286cfdc2fca4cca62d0a1b4e7dd8125a18aee59e630877f85101aa441a014104b3d8c8c5896b0ed9537ccbdcfdf3f05cd4299988c72d078b841e0491bab198702c4befaa3da367c117c7c6217cd478c54b572e13de6ddd22c948f4b66c1562b5fffffffffb862000126a61dba547524f7302bc68ea177cf00f7a49c5b834c0fd397c4dfe390000008b483045022100c837ec9105ddaa75250a38e9942a624754ecacb025feb024adfa8a77914e6eff0220538a1407d7ed8b7417421113ee29c3d9699f87780907b4121068740f1eb31d68014104b3d8c8c5896b0ed9537ccbdcfdf3f05cd4299988c72d078b841e0491bab198702c4befaa3da367c117c7c6217cd478c54b572e13de6ddd22c948f4b66c1562b5ffffffffdb35b57c65cf0fcdea54bfdebda43942d728001a06a9df0404a07801c87ccd8a090000008b483045022100b00faaa1b6a7c1cbe4c47791e302bbcbf1d4fee54cb3d1195d82ef05df0f8f0702207382b68bb44e8fadb0ae7b44f22a18df93e8e8e000d28c88f4fdff78d92a8316014104b3d8c8c5896b0ed9537ccbdcfdf3f05cd4299988c72d078b841e0491bab198702c4befaa3da367c117c7c6217cd478c54b572e13de6ddd22c948f4b66c1562b5ffffffff539ff8e14dab98db92dbbaff03dda50136470bb30bf9fb5b844eb356bc31362d1f0000008b48304502205e41d2112c190396173562d7957b16e0bba64a40adbe466cfe98778d30d91fa20221009f62ac2e345dbd16639b4269c86f156c050e5747013d2a452cdd8c25b8c9aeb9014104b3d8c8c5896b0ed9537ccbdcfdf3f05cd4299988c72d078b841e0491bab198702c4befaa3da367c117c7c6217cd478c54b572e13de6ddd22c948f4b66c1562b5ffffffffbc0dabbf27d0a58f0e2f5a36c11e7f270737ddc92ef0d8d1baacdeff24f39ed7110000008a473044021f3cfe420bd8a5baca342a3df2501f03165e8b8b76fea6fbc82dd05047c99fcd022100bfa829bce78d4f463abefbba943ea54dbbd931b5d7712e263eaf76d2779cf053014104b3d8c8c5896b0ed9537ccbdcfdf3f05cd4299988c72d078b841e0491bab198702c4befaa3da367c117c7c6217cd478c54b572e13de6ddd22c948f4b66c1562b5ffffffff023011e100000000001976a91431b07b8df3c19573388bb688b4fd89f6233f5d7988acf4f31400000000001976a914d17e062579b71bfe199a80991a253d929f8bd35b88ac00000000',
                'inputs' => [
                    [
                        "txid" => "5a373fd13679fc55f479f08bef25d5e808031f97331a48f950ced89d7e99c269",
                        "vout" => 31,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "29b509aa81cb4115645b536c14e6c0f7699f5e2228d95c79300f23004aae9aab",
                        "vout" => 123,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "e59686315e67427c465d6febe77ce1b93af66f1e25590353743fa95a4c1836c0",
                        "vout" => 1,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "00078ef8003e86b1ec57a69842e4a64e54d7dea9dddfb4124f257cb3bf077172",
                        "vout" => 17,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "fe4d7c39fdc034b8c5497a0ff07c17ea68bc02734f5247a5db616a12002086fb",
                        "vout" => 57,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "8acd7cc80178a00404dfa9061a0028d74239a4bddebf54eacd0fcf657cb535db",
                        "vout" => 9,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "2d3631bc56b34e845bfbf90bb30b473601a5dd03ffbadb92db98ab4de1f89f53",
                        "vout" => 31,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ],
                    [
                        "txid" => "d79ef324ffdeacbad1d8f02ec9dd3707277f1ec1365a2f0e8fa5d027bfab0dbc",
                        "vout" => 17,
                        "scriptPubKey" => "76a914d17e062579b71bfe199a80991a253d929f8bd35b88ac"
                    ]
                ],
                'outputs' => [
                    "1L6hCPsCq7C5rNzq7wSyu4eaQCq8LeipmG" => 0.01373172
                ]
            ]
        ];

        foreach($data as $test) {
            $this->assertTrue(RawTransaction::validate_signed_transaction($test['tx'], json_encode($test['inputs']),'00'));
        }
    }

    public function testTxHash() {
        // https://www.blocktrail.com/BTC/tx/6395e16150c6b4c3499740c7b9ea902747410d9e1ca8398d81d0ddd2e4bf2822
        $hash = "6395e16150c6b4c3499740c7b9ea902747410d9e1ca8398d81d0ddd2e4bf2822";
        $raw = "010000000178c07b9b8383f28f70d6a386ebec67ca38b2320a0f797449c42faab463776d07010000006b4830450221009d35a724c2924643e8d53e7b9703748aac09eb636a30b61909f47e1b86bd5b3d0220364cdf7fc0c37ed4f78c10b96baa49b7b9f3b5a65a12c19b0f50ab77f1ca4ae10121034e68233e53095310b4f3041f7865bc928827afee62cc5aa2143465b3bb64cb2dffffffff02409c00000000000017a914a1e64962519b43be719392eab45eed5cf1198f4087b0e74c00000000001976a914fb11f9fe83b646d982a3d4df8c5a5da44143ac1888ac00000000";

        $tx = RawTransaction::decode($raw);

        $this->assertEquals($tx['txid'], RawTransaction::_flip_byte_order($hash));
        $this->assertEquals($hash, RawTransaction::_flip_byte_order($tx['txid']));
        $this->assertEquals($hash, RawTransaction::hash_from_raw($raw));
        $this->assertEquals($hash, RawTransaction::hash_from_txid($tx['txid']));
    }


    public function testP2SHMultisig() {
        $n = 3;
        $m = 2;

        $k = [];
        $pk_list = [];

        for($i = 0; $i < $n; $i++){
            $k[$i] = BitcoinLib::get_new_key_set();
            $pk_list[] = $k[$i]['pubKey'];
        }

        $multisig = RawTransaction::create_multisig($m, $pk_list);

        $this->assertTrue(!!$multisig['address']);
        $this->assertTrue(BitcoinLib::validate_address($multisig['address']));
    }


};
