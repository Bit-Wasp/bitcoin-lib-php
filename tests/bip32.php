<?php

require_once(dirname(__FILE__).'/../application/libraries/BitcoinLib.php');
require_once(dirname(__FILE__).'/../application/libraries/BIP32.php');


echo BitcoinLib::base58_decode('mhXLvYbWuZjsdmT7XKkrRiq8PCBQzga4YU')."\n";
// Load a 128 bit key, and convert this to extended key format.
$master = BIP32::master_key('41414141414141414141414141414141414141');
$def = "0'";

echo "Master key m : {$master[0]} \n";
// Define what derivation you wish to calculate.

echo "Want m/$def  - note that all depth=1 keys are hardened. \n\n";
$key = BIP32::build_key($master, $def);		// Build the extended key

// Display private extended key and the address that's derived from it.
echo "Generated key: {$key[1]} - {$key[0]}\n";
echo "             : ".BIP32::key_to_address($key[0])."\n\n";

// Convert the extended private key to the public key, and display the 
// address that's derived from it.
$pub = BIP32::extended_private_to_public($key);
echo "Public key   : {$pub[1]} - {$pub[0]}\n";
echo "             : ".BIP32::key_to_address($pub[0])."\n";

$nextpub = BIP32::build_key($pub, '0');
echo "             : {$nextpub[1]} - {$nextpub[0]}\n";
