/*
 * This code has not been reviewed.
 * Do not use or deploy this code before reviewing it personally first.
 */
pragma solidity ^0.5.0;

import "openzeppelin-solidity/contracts/math/SafeMath.sol";
import "openzeppelin-solidity/contracts/ownership/Ownable.sol";
import "openzeppelin-solidity/contracts/token/ERC20/IERC20.sol";

import "../../roles/Pausable.sol";
import "../../roles/CertificateSignerRole.sol";
import "../../roles/AllowlistedRole.sol";
import "../../roles/BlocklistedRole.sol";
import "../../roles/TokenLimit.sol";

import "erc1820/contracts/ERC1820Client.sol";
import "../../interface/ERC1820Implementer.sol";

import "../../IERC1400.sol";

import "./IERC1400TokensValidator.sol";

/**
 * @notice Interface to the Minterrole contract
 */
interface IMinterRole {
  function isMinter(address account) external view returns (bool);
}


contract ERC1400TokensValidator is IERC1400TokensValidator, Ownable, Pausable, CertificateSignerRole, AllowlistedRole, BlocklistedRole, TokenLimit, ERC1820Client, ERC1820Implementer {
  using SafeMath for uint256;

  string constant internal ERC1400_TOKENS_VALIDATOR = "ERC1400TokensValidator";

  bytes4 constant internal ERC20_TRANSFER_ID = bytes4(keccak256("transfer(address,uint256)"));
  bytes4 constant internal ERC20_TRANSFERFROM_ID = bytes4(keccak256("transferFrom(address,address,uint256)"));

  // Mapping from token to token controllers.
  mapping(address => address[]) internal _tokenControllers;

  // Mapping from (token, operator) to token controller status.
  mapping(address => mapping(address => bool)) internal _isTokenController;

  // Mapping from token to allowlist activation status.
  mapping(address => bool) internal _allowlistActivated;

  // Mapping from token to blocklist activation status.
  mapping(address => bool) internal _blocklistActivated;

  // Mapping from token to certificate activation status.
  mapping(address => CertificateValidation) internal _certificateActivated;

  // Mapping from token to transaction limit activation status.
  mapping(address => bool) internal _transactionLimitActivated;

  // Mapping from token to account limit activation status.
  mapping(address => bool) internal _accountLimitActivated;

  // Mapping from (token, partition) to partition expiry activation status.
  mapping(address => mapping(bytes32 => bool)) internal _tokenPartitionExpiryActivated;

  // Mapping from (token, patition) to partition expiry timestamp
  mapping(address => mapping(bytes32 => uint256)) internal _tokenPartitionExpiryTimestamp;

  // Mapping from (token, certificateNonce) to "used" status to ensure a certificate can be used only once
  mapping(address => mapping(address => uint256)) internal _usedCertificateNonce;

  // Mapping from (token, certificateSalt) to "used" status to ensure a certificate can be used only once
  mapping(address => mapping(bytes32 => bool)) internal _usedCertificateSalt;

  // Mapping from token to partition granularity activation status.
  mapping(address => bool) internal _granularityByPartitionActivated;

  // Mapping from token to holds activation status.
  mapping(address => bool) internal _holdsActivated;

  // Mapping from (token, partition) to partition granularity.
  mapping(address => mapping(bytes32 => uint256)) internal _granularityByPartition;

  enum CertificateValidation {
    None,
    NonceBased,
    SaltBased
  }

  /**
   * @dev Modifier to verify if sender is a token controller.
   */
  modifier onlyTokenController(address token) {
    require(
      msg.sender == token ||
      msg.sender == Ownable(token).owner() ||
      _isTokenController[token][msg.sender],
      "Sender is not a token controller."
    );
    _;
  }

  /**
   * @dev Modifier to verify if sender is a pauser.
   */
  modifier onlyPauser(address token) {
    require(
      msg.sender == token ||
      msg.sender == Ownable(token).owner() ||
      _isTokenController[token][msg.sender] ||
      isPauser(token, msg.sender),
      "Sender is not a pauser"
    );
    _;
  }

  /**
   * @dev Modifier to verify if sender is a pauser.
   */
  modifier onlyCertificateSigner(address token) {
    require(
      msg.sender == token ||
      msg.sender == Ownable(token).owner() ||
      _isTokenController[token][msg.sender] ||
      isCertificateSigner(token, msg.sender),
      "Sender is not a certificate signer"
    );
    _;
  }

  /**
   * @dev Modifier to verify if sender is an allowlist admin.
   */
  modifier onlyAllowlistAdmin(address token) {
    require(
      msg.sender == token ||
      msg.sender == Ownable(token).owner() ||
      _isTokenController[token][msg.sender] ||
      isAllowlistAdmin(token, msg.sender),
      "Sender is not an allowlist admin"
    );
    _;
  }

  /**
   * @dev Modifier to verify if sender is a blocklist admin.
   */
  modifier onlyBlocklistAdmin(address token) {
    require(
      msg.sender == token ||
      msg.sender == Ownable(token).owner() ||
      _isTokenController[token][msg.sender] ||
      isBlocklistAdmin(token, msg.sender),
      "Sender is not a blocklist admin"
    );
    _;
  }

   /**
    * @dev Modifier to verify if sender is an token limit admin.
    */
  modifier onlyTokenLimitAdmin(address token) {
    require(
      msg.sender == token ||
      msg.sender == Ownable(token).owner() ||
      isTokenLimitAdmin(token, msg.sender) ||
      isOwner(),
      "Sender is not a token limit admin"
    );
    _;
  }

  constructor() public {
    ERC1820Implementer._setInterface(ERC1400_TOKENS_VALIDATOR);
  }

  /**
   * @dev Get the list of token controllers for a given token.
   * @return Setup of a given token.
   */
  function retrieveTokenSetup(address token) external view returns (CertificateValidation, bool, bool, bool, bool, address[] memory) {
    return (
      _certificateActivated[token],
      _allowlistActivated[token],
      _blocklistActivated[token],
      _granularityByPartitionActivated[token],
      _holdsActivated[token],
      _tokenControllers[token]
    );
  }

  /**
   * @dev Register token setup.
   */
  function registerTokenSetup(
    address token,
    CertificateValidation certificateActivated,
    bool allowlistActivated,
    bool blocklistActivated,
    bool granularityByPartitionActivated,
    bool holdsActivated,
    address[] calldata operators
  ) external onlyTokenController(token) {
    _certificateActivated[token] = certificateActivated;
    _allowlistActivated[token] = allowlistActivated;
    _blocklistActivated[token] = blocklistActivated;
    _granularityByPartitionActivated[token] = granularityByPartitionActivated;
    _holdsActivated[token] = holdsActivated;
    _setTokenControllers(token, operators);
  }

  /**
   * @dev Set list of token controllers for a given token.
   * @param token Token address.
   * @param operators Operators addresses.
   */
  function _setTokenControllers(address token, address[] memory operators) internal {
    for (uint i = 0; i<_tokenControllers[token].length; i++){
      _isTokenController[token][_tokenControllers[token][i]] = false;
    }
    for (uint j = 0; j<operators.length; j++){
      _isTokenController[token][operators[j]] = true;
    }
    _tokenControllers[token] = operators;
  }

  /**
   * @dev Get the list of custom extension setup for a given token.
   * @return Setup of a given token.
   */
  function retrieveCustomExtensionSetup(address token) external view returns (bool, bool) {
    return (
      _transactionLimitActivated[token],
      _accountLimitActivated[token]
    );
  }

  /**
   * @dev Register custom extension setup.
   */
  function registerCustomExtensionSetup(
    address token,
    bool transactionLimitActivated,
    bool accountLimitActivated
  ) external onlyTokenLimitAdmin(token) {
     _transactionLimitActivated[token] = transactionLimitActivated;
     _accountLimitActivated[token] = accountLimitActivated;
  }

  /**
   * @dev Register partition extension setup.
   */
  function registerPartitionExtensionSetup(
    address token,
    bytes32 partition,
    bool partitionExpiryActivated
  ) external onlyTokenLimitAdmin(token) {
    _tokenPartitionExpiryActivated[token][partition] = partitionExpiryActivated;
  }

  /**
   * @dev Verify if a token transfer can be executed or not, on the validator's perspective.
   * @param token Token address.
   * @param payload Payload of the initial transaction.
   * @param partition Name of the partition (left empty for ERC20 transfer).
   * @param operator Address which triggered the balance decrease (through transfer or redemption).
   * @param from Token holder.
   * @param to Token recipient for a transfer and 0x for a redemption.
   * @param value Number of tokens the token holder balance is decreased by.
   * @param data Extra information.
   * @param operatorData Extra information, attached by the operator (if any).
   * @return 'true' if the token transfer can be validated, 'false' if not.
   */
  function canValidate(
    address token,
    bytes calldata payload,
    bytes32 partition,
    address operator,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata operatorData
  ) // Comments to avoid compilation warnings for unused variables.
    external
    view
    returns(bool)
  {
    // (bool canValidateToken,,) = _canValidateCertificateToken(token, payload, operator, operatorData.length != 0 ? operatorData : data);

    bool canValidateToken = _canValidateAllowlistAndBlocklistToken(token, payload, from, to);

    canValidateToken = canValidateToken && !paused(token);

    canValidateToken = canValidateToken && _canValidateGranularToken(token, partition, value);

    canValidateToken = canValidateToken && _canValidateConditionalPayment(token, payload, partition, from, to, value);

    return canValidateToken;
  }

  /**
   * @dev Function called by the token contract before executing a transfer.
   * @param payload Payload of the initial transaction.
   * @param partition Name of the partition (left empty for ERC20 transfer).
   * @param operator Address which triggered the balance decrease (through transfer or redemption).
   * @param from Token holder.
   * @param to Token recipient for a transfer and 0x for a redemption.
   * @param value Number of tokens the token holder balance is decreased by.
   * @param data Extra information.
   * @param operatorData Extra information, attached by the operator (if any).
   * @return 'true' if the token transfer can be validated, 'false' if not.
   */
  function tokensToValidate(
    bytes calldata payload,
    bytes32 partition,
    address operator,
    address from,
    address to,
    uint value,
    bytes calldata data,
    bytes calldata operatorData
  ) // Comments to avoid compilation warnings for unused variables.
    external
  {
    require(_canValidateAllowlistAndBlocklistToken(msg.sender, payload, from, to), "54"); // 0x54	transfers halted (contract paused)

    require(!paused(msg.sender), "54"); // 0x54	transfers halted (contract paused)

    require(_canValidateGranularToken(msg.sender, partition, value), "50"); // 0x50	transfer failure

    require(_canValidateConditionalPayment(msg.sender, payload, partition, from, to, value), "59"); // 0x59	conditional payment failed
  }

  /**
   * @dev Verify if a token transfer can be executed or not, on the validator's perspective.
   * @return 'true' if the token transfer can be validated, 'false' if not.
   * @return hold ID in case a hold can be executed for the given parameters.
   */
  function _canValidateAllowlistAndBlocklistToken(
    address token,
    bytes memory payload,
    address from,
    address to
  ) // Comments to avoid compilation warnings for unused variables.
    internal
    view
    returns(bool)
  {
    if(
      !_functionSupportsCertificateValidation(payload) ||
      _certificateActivated[token] == CertificateValidation.None
    ) {
      if(_allowlistActivated[token]) {
        if(from != address(0) && !isAllowlisted(token, from)) {
          return false;
        }
        if(to != address(0) && !isAllowlisted(token, to)) {
          return false;
        }
      }
      if(_blocklistActivated[token]) {
        if(from != address(0) && isBlocklisted(token, from)) {
          return false;
        }
        if(to != address(0) && isBlocklisted(token, to)) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * @dev Verify if a token transfer can be executed or not, on the validator's perspective.
   * @return 'true' if the token transfer can be validated, 'false' if not.
   * @return hold ID in case a hold can be executed for the given parameters.
   */
  function _canValidateConditionalPayment(
    address token,
    bytes memory payload,
    bytes32 partition,
    address from,
    address to,
    uint value
  ) // Comments to avoid compilation warnings for unused variables.
    internal
    view
    returns(bool)
  {
    if(_transactionLimitActivated[token]) {
      uint transLimit = getTransactionLimit(token, from);
      if (
        transLimit > 0 &&
        value > transLimit
      ) {
        return false;
      }
    }

   if(_accountLimitActivated[token]) {
     uint recipientBalance = IERC20(msg.sender).balanceOf(to);
     uint accountLimit = getMaxAccountBalane(token, to);
      if (
        accountLimit > 0 &&
        (recipientBalance + value) > accountLimit
      ) {
        return false;
      }
    }

    //Do not validate transfers when the partition has expired
    if (_getPartitionExpiryActivated(token, partition)) {
      if (_getPartitionExpiryStatus(token, partition)) {
        return false;
      }
    }

    return true;
  }
  /**
   * @dev Verify if a token transfer can be executed or not, on the validator's perspective.
   * @return 'true' if the token transfer can be validated, 'false' if not.
   * @return hold ID in case a hold can be executed for the given parameters.
   */
  function _canValidateGranularToken(
    address token,
    bytes32 partition,
    uint value
  )
    internal
    view
    returns(bool)
  {
    if(_granularityByPartitionActivated[token]) {
      if(
        _granularityByPartition[token][partition] > 0 &&
        !_isMultiple(_granularityByPartition[token][partition], value)
      ) {
        return false;
      } 
    }

    return true;
  }

/**
   * @dev Get partition expiry activation status
   * @param token Address of the token.
   * @param partition Name of the partition.
   * @return Expiry activation status of the partition.
   */
  function getPartitionExpiryActivated(address token, bytes32 partition) external view returns (bool) {
    return _getPartitionExpiryActivated(token, partition);
  }
  
  /**
   * @dev Get partition expiry status
   * @param token Address of the token.
   * @param partition Name of the partition.
   * @return Expiry status of the partition.
   */
  function getPartitionExpiryStatus(address token, bytes32 partition) external view returns (bool) {
    return _getPartitionExpiryStatus(token, partition);
  }
  
  /**
   * @dev Get partition expiry timestamp
   * @param token Address of the token.
   * @param partition Name of the partition.
   * @return Expiry timestamp of the partition.
   */
  function getPartitionExpiryTimestamp(address token, bytes32 partition) external view returns (uint256) {
    return _getPartitionExpiryTimestamp(token, partition);
  }

  /**
   * @dev Set partition expiry activation timestamp
   * @param token Address of the token.
   * @param partition Name of the partition.
   * @param expiryTimestamp Expiry timestamp of the partition.
   * @return Expiry activation status of the partition.
   */
  function setPartitionExpiryTimestamp(
    address token,
    bytes32 partition,
    uint256 expiryTimestamp
  )
    external
    onlyTokenLimitAdmin(token)
  {
    require(_getPartitionExpiryActivated(token, partition) == false, "Partition expiry is already activated");
    require(expiryTimestamp > now, "Partition expiry timestamp must be in the future");

    _tokenPartitionExpiryActivated[token][partition] = true;
    _tokenPartitionExpiryTimestamp[token][partition] = expiryTimestamp;
  }

  /**
   * @dev Allow controllers to move expired tokens
   * @param token Address of the token.
   * @param partition Name of the partition.
   * @param recipient Address of the recipient.
   * @return Transfer status.
   */
  function transferExpiredTokens(
    address token,
    bytes32 partition,
    address recipient
  )
    external
    onlyTokenLimitAdmin(token)
  {
    require(_getPartitionExpiryStatus(token, partition), "Partition must have expired");
    // todo: move tokens
  }

  /**
   * @dev Get partition expiry activation status
   * @param token Address of the token.
   * @param partition Name of the partition.
   * @return Expiry activation status of the partition.
   */
  function _getPartitionExpiryActivated(address token, bytes32 partition) internal view returns (bool) {
    return _tokenPartitionExpiryActivated[token][partition];
  }

  /**
   * @dev Get partition expiry status
   * @param token Address of the token.
   * @param partition Name of the partition.
   * @return Expiry status of the partition.
   */
  function _getPartitionExpiryStatus(address token, bytes32 partition) internal view returns (bool) {
    require(_getPartitionExpiryActivated(token, partition), "Partition expiry is not activated");
    return _tokenPartitionExpiryTimestamp[token][partition] < now;
  }
  
  /**
   * @dev Get partition expiry timestamp
   * @param token Address of the token.
   * @param partition Name of the partition.
   * @return Expiry timestamp of the partition.
   */
  function _getPartitionExpiryTimestamp(address token, bytes32 partition) internal view returns (uint256) {
    require(_getPartitionExpiryActivated(token, partition), "Partition expiry is not activated");
    return _tokenPartitionExpiryTimestamp[token][partition];
  }

  /**
   * @dev Get granularity for a given partition.
   * @param token Token address.
   * @param partition Name of the partition.
   * @return Granularity of the partition.
   */
  function granularityByPartition(address token, bytes32 partition) external view returns (uint256) {
    return _granularityByPartition[token][partition];
  }
  
  /**
   * @dev Set partition granularity
   */
  function setGranularityByPartition(
    address token,
    bytes32 partition,
    uint256 granularity
  )
    external
    onlyTokenController(token)
  {
    _granularityByPartition[token][partition] = granularity;
  }

  /**
   * @dev Check expiration time.
   */
  function _checkExpiration(uint256 expiration) private view {
    require(expiration > now || expiration == 0, "Expiration date must be greater than block timestamp or zero");
  }

  /**
   * @dev Check is expiration date is past.
   */
  function _isExpired(uint256 expiration) internal view returns (bool) {
    return expiration != 0 && (now >= expiration);
  }

  /**
   * @dev Check if validator is activated for the function called in the smart contract.
   * @param payload Payload of the initial transaction.
   * @return 'true' if the function requires validation, 'false' if not.
   */
  function _functionSupportsCertificateValidation(bytes memory payload) internal pure returns(bool) {
    bytes4 functionSig = _getFunctionSig(payload);
    if(_areEqual(functionSig, ERC20_TRANSFER_ID) || _areEqual(functionSig, ERC20_TRANSFERFROM_ID)) {
      return false;
    } else {
      return true;
    }
  }

  /**
   * @dev Extract function signature from payload.
   * @param payload Payload of the initial transaction.
   * @return Function signature.
   */
  function _getFunctionSig(bytes memory payload) internal pure returns(bytes4) {
    return (bytes4(payload[0]) | bytes4(payload[1]) >> 8 | bytes4(payload[2]) >> 16 | bytes4(payload[3]) >> 24);
  }

  /**
   * @dev Check if 2 variables of type bytes4 are identical.
   * @return 'true' if 2 variables are identical, 'false' if not.
   */
  function _areEqual(bytes4 a, bytes4 b) internal pure returns(bool) {
    for (uint256 i = 0; i < a.length; i++) {
      if(a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * @dev Check if 'value' is multiple of 'granularity'.
   * @param granularity The granularity that want's to be checked.
   * @param value The quantity that want's to be checked.
   * @return 'true' if 'value' is a multiple of 'granularity'.
   */
  function _isMultiple(uint256 granularity, uint256 value) internal pure returns(bool) {
    return(value.div(granularity).mul(granularity) == value);
  }

  /**
   * @dev Get state of certificate (used or not).
   * @param token Token address.
   * @param sender Address whom to check the counter of.
   * @return uint256 Number of transaction already sent for this token contract.
   */
  function usedCertificateNonce(address token, address sender) external view returns (uint256) {
    return _usedCertificateNonce[token][sender];
  }

  /**
   * @dev Get state of certificate (used or not).
   * @param token Token address.
   * @param salt First 32 bytes of certificate whose validity is being checked.
   * @return bool 'true' if certificate is already used, 'false' if not.
   */
  function usedCertificateSalt(address token, bytes32 salt) external view returns (bool) {
    return _usedCertificateSalt[token][salt];
  }
}