<?php

use BitWasp\BitcoinLib\BitcoinLib;
use BitWasp\BitcoinLib\RawTransaction;

require_once(__DIR__. '/../vendor/autoload.php');

$m				= 2;
$public_keys 	= array('0379ddc228d8c44a85ae30c877a6b037ec3d627e0507f223a0412790a83a46cd5f',
						'024d1cf2ca917f4d679fc02df2a39c0a8110a1b6935b27ae6762a0ceeec7752801',
						'0258f70f6400aa6f60ff0d21c3aaf1ca236d177877d2b9ad9d2c55280e375ab2d2');

// Create redeem script
$redeem_script	= RawTransaction::create_redeem_script($m, $public_keys);

// Obtain 20-byte hash of script
$hash160		= BitcoinLib::hash160($redeem_script);

// Convert to address with version 0x05.
$address 		= BitcoinLib::hash160_to_address($hash160, '05');

// Display data
$c = 0;
echo "Public Keys\n";
for ($i = 0; $i < count($public_keys); $i++) {
	echo "$i : ".$public_keys[$i]."\n";
}

echo "\nRedeem Script\n";
echo "$redeem_script\n\n";

echo "Hash160\n";
echo "$hash160\n\n";

echo "Address\n";
echo "$address\n\n";
