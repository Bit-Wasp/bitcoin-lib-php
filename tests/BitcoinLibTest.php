<?php

use BitWasp\BitcoinLib\BitcoinLib as BitcoinLib;

require_once(__DIR__. '/../vendor/autoload.php');

class BitcoinLibTest extends PHPUnit_Framework_TestCase
{
	public $bitcoin;
	public $testHexEncode_i;
	
	public function __construct() {

	}
	
	public function setup() {
        $this->bitcoin = new BitcoinLib();
    }
    
	public function tearDown() {
        $this->bitcoin = null;
    }
	
	//////////////////////////////////////////////////////
	// hex_encode() test functions
	//
	public function _testHexEncode_result($hex) {
		$this->assertEquals($this->testHexEncode_i, hexdec($hex));
	}
	
	public function _testHexEncode_length($hex) {
		$this->assertTrue(strlen($hex)%2 == 0);
	}

	public function testHexEncode() 
	{
		for($this->testHexEncode_i = 0; $this->testHexEncode_i < 500; ($this->testHexEncode_i++)) {
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
		for($i = 0; $i < 500; $i++)
		{
			$length = mt_rand(1, 32);
			$hex = (string)bin2hex(openssl_random_pseudo_bytes($length));
			$this->assertTrue(ctype_xdigit($hex));
		}
	}
	///////////////////////////////////////////////////////


	///////////////////////////////////////////////////////
	// hex_decode() test functions
	public function _testHexDecode_result($dec, $real_val) {
		$this->assertEquals($dec, $real_val);
	}

	public function testHexDecodeBaseConvert()
	{
		// Base_Convert handles UP TO 8 bytes.
		for($i = 0; $i < 1000; $i++)
		{
            $this->setup();
			$length = mt_rand(1, 7);
			// Generate a random length hex string.
			$hex = (string)bin2hex(openssl_random_pseudo_bytes($length));
			// Get real decimal result.
			$dec = base_convert($hex, 16, 10); // handles big ints better than hexdec.
			$this->assertEquals($this->bitcoin->hex_decode($hex), $dec);
            $this->tearDown();
		}
	}
	
	public function testHexDecodeGMP()
	{
		// GMP has no real upper limit on the number of bytes!
		for($i = 0; $i < 1000; $i++)
		{
            $this->setup();
			$length = mt_rand(1, 5000);
			// Generate a random length hex string.
			$hex = (string)bin2hex(openssl_random_pseudo_bytes($length));
			// Get real decimal result.
			$dec = gmp_strval(gmp_init($hex,16),10);
			$this->assertEquals($this->bitcoin->hex_decode($hex), $dec);
            $this->tearDown();
		}
	}	
	///////////////////////////////////////////////////////
	
	
	///////////////////////////////////////////////////////
	// base58_encode() & base58_decode() tests for consistency
	public function testBase58FunctionsForConsistency() {
		for ($i = 0; $i < 500; $i++)
		{
            $this->setup();
			// Generate a random length hex string.
			$hex = (string)bin2hex(openssl_random_pseudo_bytes(20));
			$encode = $this->bitcoin->base58_encode($hex);
			$decode = $this->bitcoin->base58_decode($encode);
			
			$this->assertTrue($hex == $decode);
            $this->tearDown();
		}
	}

   /* public function _testBase58EncodeValues($data, $equals) {
        $this->assertEquals($data, $equals);
    }*/

   public function testBase58EncodeValues() {
        // Taken from Bitcoin Core's ./src/tests/data/base58_encode_decode.json file
        $tests = ["" => "",
            "61" => "2g",
            "626262" => "a3gV",
            "636363" => "aPEr",
            "73696d706c792061206c6f6e6720737472696e67" =>"2cFupjhnEsSn59qHXstmK2ffpLv2",
            "00eb15231dfceb60925886b67d065299925915aeb172c06647" => "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
            "516b6fcd0f" => "ABnLTmg",
            "bf4f89001e670274dd" => "3SEo3LWLoPntC",
            "572e4794" => "3EFU7m",
            "ecac89cad93923c02321" => "EJDM8drfXA6uyA",
            "10c8511e" => "Rt5zm",
            "00000000000000000000" => "1111111111"];
        foreach($tests as $data => $equals){
            $this->setup();
            $res = $this->bitcoin->base58_encode(trim($data));
            $this->assertEquals($res, $equals);
            $this->tearDown();
        }
    }
	///////////////////////////////////////////////////////
	
	///////////////////////////////////////////////////////
	// base58_check testing
	public function testBase58CheckEncode()
	{
		for ($i = 0; $i < 500; $i++)
		{
            $this->setup();
			// random, 20-byte string.
			$hex = (string)bin2hex(openssl_random_pseudo_bytes(20));
			
			$encode = $this->bitcoin->base58_encode_checksum('00'.$hex);
			$decode = $this->bitcoin->base58_decode_checksum($encode);
			$this->assertTrue($this->bitcoin->validate_address($encode,'00'));
			$this->assertTrue($hex == $decode);
			// Check that the string was encoded correctly w/ checksum

			$check2 = $this->bitcoin->hash160_to_address($hex, '00');
			// Check that both ways of generating the address result in the same thing.
			$this->assertTrue($this->bitcoin->validate_address($check2,'00'));
			$this->assertTrue($check2 == $encode);
            $this->tearDown();
		}
	}

    public function testKeyConversion() {
        $tests = ["5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj" => "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ",
            "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3" => "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ",
            "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw" => "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs"];

        foreach($tests as $priv_key => $true_address) {
            $this->setup();
            $priv_key = trim($priv_key);

            $priv_key_info = $this->bitcoin->WIF_to_private_key($priv_key);
            $pubkey = $this->bitcoin->private_key_to_public_key($priv_key_info['key'], $priv_key_info['is_compressed']);
            $address = $this->bitcoin->public_key_to_address($pubkey, '00');
            $this->assertEquals($address, $true_address);

            $this->tearDown();
        }
    }


	///////////////////////////////////////////////////////

    public function testGetPrivKeyWif()
    {
        for($i = 0; $i < 50; $i++)
        {
            $this->setup();
            $hex = (string)str_pad(bin2hex(openssl_random_pseudo_bytes(32)),64,'0',STR_PAD_LEFT);
            $wif = $this->bitcoin->private_key_to_WIF($hex, FALSE, '00');
            $key = $this->bitcoin->WIF_to_private_key($wif);

            $this->assertTrue($key['key'] == $hex);
            $this->tearDown();
        }
    }

    public function testImportPublicKey()
    {
        for($i = 0; $i < 10; $i++)
        {
            $this->setup();
            $hex = (string)str_pad(bin2hex(openssl_random_pseudo_bytes(32)),64,'0',STR_PAD_LEFT);
            $public = $this->bitcoin->private_key_to_public_key($hex, FALSE);
            $import = $this->bitcoin->import_public_key($public);

            $this->assertTrue($import !== FALSE);
            $this->tearDown();
        }

    }

    public function testProducingStrongRNG()
    {
        for($i = 0; $i < 100; $i++)
        {
            $is_strong = FALSE;
            $hex = (string)str_pad(bin2hex(openssl_random_pseudo_bytes(32, $is_strong)),64,'0',STR_PAD_LEFT);
            $this->assertTrue($is_strong);
        }
    }

    public function testPublicKeyCompressionFaultKeys()
    {
        for($i = 0; $i < 15; $i++)
        {
            $this->setup();
            $hex = (string)str_pad(bin2hex(openssl_random_pseudo_bytes(32)),64,'0',STR_PAD_LEFT);
            $public = $this->bitcoin->private_key_to_public_key($hex, FALSE);
            $compress = $this->bitcoin->compress_public_key($public);
            $decompress = $this->bitcoin->decompress_public_key($compress);

            $this->assertTrue($decompress['public_key'] == $public);
            $this->tearDown();
        }
    }

    public function testPublicKeyCompression()
    {
        for($i = 0; $i < 15; $i++)
        {
            $this->setup();
            $key = $this->bitcoin->get_new_private_key();
            $public = $this->bitcoin->private_key_to_public_key($key, FALSE);
            $compress = $this->bitcoin->compress_public_key($public);
            $decompress = $this->bitcoin->decompress_public_key($compress);

            $this->assertTrue($decompress['public_key'] == $public);
            $this->tearDown();
        }
    }

    public function testValidatePublicKey() {
        for($i = 0; $i < 15; $i++)
        {
            $this->setup();
            $set = $this->bitcoin->get_new_key_set('00');
            $this->assertTrue($this->bitcoin->validate_public_key($set['pubKey']));
            $this->tearDown();
        }
    }

    public function testPrivateKeyValidation()
    {
        $val = FALSE;
        for($i = 0; $i < 50; $i++)
        {
            $this->setup();
            $key = $this->bitcoin->get_new_key_set('00', $val);
            $val = ($val == FALSE) ? TRUE : FALSE;
            $this->assertTrue($this->bitcoin->validate_WIF($key['privWIF'], '80'));
            $this->tearDown();
        }
    }

    public function testImportUncompOrCompPublicKey()
    {
        $val = FALSE;
        for($i = 0; $i < 50; $i++)
        {
            $this->setup();
            $key = $this->bitcoin->get_new_private_key();
            $unc = $this->bitcoin->private_key_to_public_key($key, FALSE);
            $pubkey = $this->bitcoin->private_key_to_public_key($key, $val);
            $val = ($val == FALSE) ? TRUE : FALSE;
            $this->assertTrue($unc == $this->bitcoin->import_public_key($pubkey));
            $this->tearDown();
        }
    }
}

