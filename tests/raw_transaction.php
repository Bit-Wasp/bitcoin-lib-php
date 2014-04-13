<?php

require_once(dirname(__FILE__).'/../BitcoinLib.php');
require_once(dirname(__FILE__).'/../Raw_transaction.php');

/////////////////////////////
// Parameters for creation..
// Set up inputs here
$inputs = array( 
				array(	'txid' => '6737e1355be0566c583eecd48bf8a5e1fcdf2d9f51cc7be82d4393ac9555611c',
						'vout' => 0
					) 
			);
// Set up outputs here.
$outputs = array( '1PGa6cMAzzrBpTtfvQTzX5PmUxsDiFzKyW' => "0.00015");

////////////////////////////
// Parameters for signing.
// Create JSON inputs parameter
// - These can come from bitcoind, or just knowledge of the txid/vout/scriptPubKey, 
//   and redeemScript if needed.
$json_inputs = json_encode(
					array(
							array(	'txid' => '6737e1355be0566c583eecd48bf8a5e1fcdf2d9f51cc7be82d4393ac9555611c',
									'vout' => 0,
									// OP_DUP OP_HASH160 push14bytes       PkHash      OP_EQUALVERIFY OP_CHECKSIG
									'scriptPubKey' => '76a914'.'7e3f939e8ded8c0d93695310d6d481ae5da39616'.'88ac')
						)
					);
// Private Key
$private_keys = array('L2V4QgXVUyWVoMGejTj7PrRUUCEi9D9Y1AhUM8E6f5yJm7gemgN6');


// Create raw transaction
$raw_transaction = Raw_transaction::create($inputs, $outputs);


// Sign the transaction
$sign = Raw_transaction::sign($raw_transaction, $json_inputs, $private_keys);
print_r($sign);echo "\n";

