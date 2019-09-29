pragma solidity ^0.4.24;

import "./secp256k1.sol";

pragma experimental ABIEncoderV2;

contract SchnorrVerifier {
  secp256k1 public curve;
  // flag for debuging purpose, remove this before production phase
  bool public flag = false;

  struct Point {
    uint256 x; uint256 y;
  }

  struct Verification {
    Point groupKey;
    Point randomPoint;
    uint256 signature;
    bytes32 message;

    uint256 _hash;
    Point _left;
    Point _right;
  }

  constructor() {
    curve = new secp256k1();
  }

  function h(bytes32 m, uint256 a, uint256 b) public view returns (uint256) {
    return uint256(keccak256(m, 0x04, a, b));
  }

  function cmul(Point p, uint256 scalar) public view returns (uint256, uint256) {
    return curve.ecmul(p.x, p.y, scalar);
  }

  function sg(uint256 sig_s) public view returns (uint256, uint256) {
    return curve.ecmul(curve.gx(), curve.gy(), sig_s);
  }

  function cadd(Point a, Point b) public view returns (uint256, uint256) {
    return curve.ecadd(a.x, a.y, b.x, b.y);
  }

  function verify(bytes32 signature, bytes32 groupKeyX, bytes32 groupKeyY, bytes32 randomPointX, bytes32 randomPointY, bytes32 message)
    public returns (bool) {
    flag = false;
    Verification memory state;

    state.signature = uint256(signature);
    state.groupKey.x = uint256(groupKeyX);
    state.groupKey.y = uint256(groupKeyY);
    state.randomPoint.x = uint256(randomPointX);
    state.randomPoint.y = uint256(randomPointY);
    state.message = message;

    state._hash = h(state.message, state.randomPoint.x, state.randomPoint.y);

    (state._left.x, state._left.y) = sg(state.signature);
    Point memory rightPart;
    (rightPart.x, rightPart.y) = cmul(state.groupKey, state._hash);
    (state._right.x, state._right.y) = cadd(state.randomPoint, rightPart);

    flag = state._left.x == state._right.x && state._left.y == state._right.y;

    return flag;
  }
}