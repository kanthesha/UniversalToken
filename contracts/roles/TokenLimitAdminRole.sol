/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

import "openzeppelin-solidity/contracts/access/Roles.sol";


/**
 * @title TokensLimitAdminRole
 * @dev tokens limit admins are responsible for assigning and removing tokens limit on accounts.
 */
contract TokenLimitAdminRole {
    using Roles for Roles.Role;

    event TokenLimitAdminAdded(address indexed token, address indexed account);
    event TokenLimitAdminRemoved(address indexed token, address indexed account);

    // Mapping from token to tokens limit admins.
    mapping(address => Roles.Role) private _tokenLimitAdmins;

    constructor () internal {}

    modifier onlyTokenLimitAdmin(address token) {
        require(isTokenLimitAdmin(token, msg.sender));
        _;
    }

    function isTokenLimitAdmin(address token, address account) public view returns (bool) {
        return _tokenLimitAdmins[token].has(account);
    }

    function addTokenLimitAdmin(address token, address account) public {
        _addTokenLimitAdmin(token, account);
    }

    function renounceTokenLimitAdmin(address token, address account) public {
        _removeTokenLimitAdmin(token, account);
    }

    function _addTokenLimitAdmin(address token, address account) internal {
        _tokenLimitAdmins[token].add(account);
        emit TokenLimitAdminAdded(token, account);
    }

    function _removeTokenLimitAdmin(address token, address account) internal {
        _tokenLimitAdmins[token].remove(account);
        emit TokenLimitAdminRemoved(token, account);
    }
}
