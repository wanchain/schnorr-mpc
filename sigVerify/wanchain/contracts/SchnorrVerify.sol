pragma solidity ^0.4.24;

import "./Secpk256k1.sol";

library secp256k {

	function verify (
		bytes32 randomPointX,
		bytes32 randomPointY,
		bytes32 groupPointX,
		bytes32 groupPointY,
		bytes32 message)
	public
	view
	returns(bool)
	{
		
	}
	
}