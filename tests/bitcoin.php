<?php

require_once(dirname(__FILE__).'/../BitcoinLib.php');

$magic_byte = '00';

$keypair = BitcoinLib::get_new_key_set($magic_byte);
echo "Key pair: \n";print_r($keypair); echo "\n";

$compress = BitcoinLib::compress_public_key($keypair['pubKey']);
echo "Compressed public key: $compress \n";
$decompress = BitcoinLib::decompress_public_key($compress);
echo "decompressed key info: \n";
print_r($decompress);

echo "\n";
$address = BitcoinLib::public_key_to_address($compress, $magic_byte);

echo "decoding $address\n";
echo BitcoinLib::base58_decode($address);
echo "\n\n";
