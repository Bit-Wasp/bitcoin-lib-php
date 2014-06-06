<?php

use BitWasp\BitcoinLib\BitcoinLib;
use BitWasp\BitcoinLib\Electrum;

require_once(__DIR__. '/../vendor/autoload.php');

class testElectrum extends PHPUnit_Framework_TestCase {

    public function __construct() {
        $this->magic_byte = '00';
    }

    public function setup() {
        $this->electrum = new Electrum();
        $this->bitcoin = new BitcoinLib();
    }

    public function tearDown() {
        $this->electrum = null;
        $this->bitcoin = null;
    }

    public function testMnemonicDecode() {
        $mnemonic = trim('teach start paradise collect blade chill gay childhood creek picture creator branch');
        $known_seed = 'dcb85458ec2fcaaac54b71fba90bd4a5';
        $known_secexp = '74b1f6c0caae485b4aeb2f26bab3cabdec4f0b432751bd454fe11b2d2907cbda';
        $known_mpk = '819519e966729f31e1855eb75133d9e7f0c31abaadd8f184870d62771c62c2e759406ace1dee933095d15e4c719617e252f32dc0465393055f867aee9357cd52';
        $known_addresses = ["","","","",""];

        $this->setup();
        $seed = $this->electrum->decode_mnemonic($mnemonic);
        $this->assertEquals($seed, $known_seed);
        $this->tearDown();

        $this->setup();
        $mpk = $this->electrum->generate_mpk($seed);
        $this->assertEquals($mpk, $known_mpk);
        $this->tearDown();

        $this->setup();
        $secexp = $this->electrum->stretch_seed($seed);
        $secexp = $secexp['seed'];
        $this->assertEquals($secexp, $known_secexp);
        $this->tearDown();

        $count_known_addresses = count($known_addresses);
        for($i = 0; $i < $count_known_addresses; $i++) {
            $this->setup();
            $privkey = $this->electrum->generate_private_key($secexp, $i, 0);
            $address_private_deriv = $this->bitcoin->private_key_to_address($privkey, $this->magic_byte);

            $public_deriv = $this->electrum->public_key_from_mpk($mpk, $i);
            $address_private_deriv = $this->bitcoin->public_key_to_address($public_deriv, $this->magic_byte);
            $this->tearDown();
        }
    }
};
