<?php

use BitWasp\BitcoinLib\BitcoinLib as BitcoinLib;

require_once(__DIR__ . '/../vendor/autoload.php');

class BitcoinLibTest extends \PHPUnit_Framework_TestCase
{
    public $bitcoin;
    public $testHexEncode_i;

    public function __construct()
    {

    }

    public function setup()
    {
        $this->bitcoin = new BitcoinLib();
    }

    public function tearDown()
    {
        $this->bitcoin = null;
    }

    //////////////////////////////////////////////////////
    // hex_encode() test functions
    //
    public function _testHexEncode_result($hex)
    {
        $this->assertEquals($this->testHexEncode_i, hexdec($hex));
    }

    public function _testHexEncode_length($hex)
    {
        $this->assertTrue(strlen($hex) % 2 == 0);
    }

    public function testHexEncode()
    {
        for ($this->testHexEncode_i = 0; $this->testHexEncode_i < 500; ($this->testHexEncode_i++)) {
            $hex = $this->bitcoin->hex_encode((string)$this->testHexEncode_i);
            $this->_testHexEncode_result($hex);
            $this->_testHexEncode_length($hex);
        }
    }
    ///////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////
    // bin2hex() test function
    public function testBin2Hex()
    {
        for ($i = 0; $i < 500; $i++) {
            $length = mt_rand(1, 32);
            $hex = (string)bin2hex(openssl_random_pseudo_bytes($length));
            $this->assertTrue(ctype_xdigit($hex));
        }
    }
    ///////////////////////////////////////////////////////


    ///////////////////////////////////////////////////////
    // hex_decode() test functions
    public function _testHexDecode_result($dec, $real_val)
    {
        $this->assertEquals($dec, $real_val);
    }

    public function testHexDecodeBaseConvert()
    {
        // Base_Convert handles UP TO 8 bytes.
        for ($i = 0; $i < 1000; $i++) {
            $length = mt_rand(1, 7);
            // Generate a random length hex string.
            $hex = (string)bin2hex(openssl_random_pseudo_bytes($length));
            // Get real decimal result.
            $dec = base_convert($hex, 16, 10); // handles big ints better than hexdec.
            $this->assertEquals($this->bitcoin->hex_decode($hex), $dec);
        }
    }

    public function testHexDecodeGMP()
    {
        // GMP has no real upper limit on the number of bytes!
        for ($i = 0; $i < 1000; $i++) {
            $length = mt_rand(1, 5000);
            // Generate a random length hex string.
            $hex = (string)bin2hex(openssl_random_pseudo_bytes($length));
            // Get real decimal result.
            $dec = gmp_strval(gmp_init($hex, 16), 10);
            $this->assertEquals($this->bitcoin->hex_decode($hex), $dec);
        }
    }
    ///////////////////////////////////////////////////////


    ///////////////////////////////////////////////////////
    // base58_encode() & base58_decode() tests for consistency
    public function testBase58Encode()
    {
        for ($i = 0; $i < 500; $i++) {
            // Generate a random length hex string.
            $hex = (string)bin2hex(openssl_random_pseudo_bytes(20));
            $encode = $this->bitcoin->base58_encode($hex);
            $decode = $this->bitcoin->base58_decode($encode);

            $this->assertTrue($hex == $decode);
        }
    }
    ///////////////////////////////////////////////////////

    ///////////////////////////////////////////////////////
    // base58_check testing
    public function testBase58CheckEncode()
    {
        for ($i = 0; $i < 500; $i++) {
            // random, 20-byte string.
            $hex = (string)bin2hex(openssl_random_pseudo_bytes(20));

            $encode = $this->bitcoin->base58_encode_checksum('00' . $hex);
            $decode = $this->bitcoin->base58_decode_checksum($encode);
            $this->assertTrue($this->bitcoin->validate_address($encode, '00'));
            $this->assertTrue($hex == $decode);
            // Check that the string was encoded correctly w/ checksum

            $check2 = $this->bitcoin->hash160_to_address($hex, '00');
            // Check that both ways of generating the address result in the same thing.
            $this->assertTrue($this->bitcoin->validate_address($check2, '00'));
            $this->assertTrue($check2 == $encode);
        }
    }

    ///////////////////////////////////////////////////////

    public function testGetPrivKeyWif()
    {
        for ($i = 0; $i < 500; $i++) {
            $hex = (string)str_pad(bin2hex(openssl_random_pseudo_bytes(32)), 64, '0', STR_PAD_LEFT);
            $wif = $this->bitcoin->private_key_to_WIF($hex, false, '00');
            $key = $this->bitcoin->WIF_to_private_key($wif);

            $this->assertTrue($key['key'] == $hex);
        }
    }

    public function testImportPublicKey()
    {
        for ($i = 0; $i < 100; $i++) {
            $hex = (string)str_pad(bin2hex(openssl_random_pseudo_bytes(32)), 64, '0', STR_PAD_LEFT);
            $public = $this->bitcoin->private_key_to_public_key($hex, false);
            $import = $this->bitcoin->import_public_key($public);

            $this->assertTrue($import !== false);
        }

    }

    public function testProducingStrongRNG()
    {
        for ($i = 0; $i < 1000; $i++) {
            $is_strong = false;
            $hex = (string)str_pad(bin2hex(openssl_random_pseudo_bytes(32, $is_strong)), 64, '0', STR_PAD_LEFT);
            $this->assertTrue($is_strong);
        }
    }

    public function testPublicKeyCompressionFaultKeys()
    {
        for ($i = 0; $i < 150; $i++) {
            $hex = (string)str_pad(bin2hex(openssl_random_pseudo_bytes(32)), 64, '0', STR_PAD_LEFT);
            $public = $this->bitcoin->private_key_to_public_key($hex, false);
            $compress = $this->bitcoin->compress_public_key($public);
            $decompress = $this->bitcoin->decompress_public_key($compress);

            $this->assertTrue($decompress['public_key'] == $public);
        }
    }

    public function testPublicKeyCompression()
    {
        for ($i = 0; $i < 150; $i++) {
            $key = $this->bitcoin->get_new_private_key();
            $public = $this->bitcoin->private_key_to_public_key($key, false);
            $compress = $this->bitcoin->compress_public_key($public);
            $decompress = $this->bitcoin->decompress_public_key($compress);

            $this->assertTrue($decompress['public_key'] == $public);
        }
    }

    public function testValidatePublicKey()
    {
        for ($i = 0; $i < 150; $i++) {
            $set = $this->bitcoin->get_new_key_set('00');
            $this->assertTrue($this->bitcoin->validate_public_key($set['pubKey']));
        }
    }

    public function testPrivateKeyValidation()
    {
        $val = false;
        for ($i = 0; $i < 500; $i++) {
            $key = $this->bitcoin->get_new_key_set('00', $val);
            $val = ($val == false) ? true : false;
            $this->assertTrue($this->bitcoin->validate_WIF($key['privWIF'], '80'));
        }
    }

    public function testImportUncompOrCompPublicKey()
    {
        $val = false;
        for ($i = 0; $i < 500; $i++) {
            $key = $this->bitcoin->get_new_private_key();
            $unc = $this->bitcoin->private_key_to_public_key($key, false);
            $pubkey = $this->bitcoin->private_key_to_public_key($key, $val);
            $val = ($val == false) ? true : false;
            $this->assertTrue($unc == $this->bitcoin->import_public_key($pubkey));
        }
    }
}

