pragma solidity ^0.5.0;

import "./TokenLimitAdminRole.sol";


/**
 * @title TokenLimit
 * @dev contract which allows transaction and account limit on the token and token holder.
 */
contract TokenLimit is TokenLimitAdminRole {
    event AddTransactionLimit(address indexed token, address account, uint limitValue);
    event RemoveTransactionLimit(address indexed token, address account);

    event AddAccountLimit(address indexed token, address account, uint limitValue);
    event RemoveAccountLimit(address indexed token, address account);

    // Mapping from token to token paused status.
    mapping(address => mapping(address => uint)) private _maxTransactionLimit;
    mapping(address => mapping(address => uint)) private _maxAccountBalance;

    function getTransactionLimit(address token, address account) public view returns (uint) {
        return _maxTransactionLimit[token][account];
    }

    function getMaxAccountBalane(address token, address account) public view returns (uint) {
        return _maxAccountBalance[token][account];
    }

    function addTransactionLimit(address token, address account, uint value) public {
        _maxTransactionLimit[token][account] = value;
        emit AddTransactionLimit(token, account, value);
    }

    function removeTransactionLimit(address token, address account) public onlyTokenLimitAdmin(token) {
        _maxTransactionLimit[token][account] = 0;
        emit RemoveTransactionLimit(token, account);
    }

    function addAccountLimit(address token, address account, uint value) public onlyTokenLimitAdmin(token) {
        _maxAccountBalance[token][account] = value;
        emit AddAccountLimit(token, account, value);
    }

    function removeAccountLimit(address token, address account) public onlyTokenLimitAdmin(token) {
        _maxAccountBalance[token][account] = 0;
        emit RemoveAccountLimit(token, account);
    }
}
