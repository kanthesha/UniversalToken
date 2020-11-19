const { expectRevert, time } = require("@openzeppelin/test-helpers");
const { soliditySha3 } = require("web3-utils");
const { advanceTimeAndBlock } = require("./utils/time");
const { newSecretHashPair, newHoldId } = require("./utils/crypto");
const { assert } = require("chai");
const Account = require('eth-lib/lib/account');

const ERC1400HoldableCertificate = artifacts.require("ERC1400HoldableCertificateToken");
const ERC1820Registry = artifacts.require("ERC1820Registry");

const ERC1400TokensValidator = artifacts.require("ERC1400TokensValidator");
const ERC1400TokensValidatorMock = artifacts.require("ERC1400TokensValidatorMock");
const ERC1400TokensChecker = artifacts.require("ERC1400TokensChecker");
const FakeERC1400Mock = artifacts.require("FakeERC1400Mock");

const PauserMock = artifacts.require("PauserMock.sol");
const CertificateSignerMock = artifacts.require("CertificateSignerMock.sol");
const AllowlistMock = artifacts.require("AllowlistMock.sol");
const BlocklistMock = artifacts.require("BlocklistMock.sol");

const ClockMock = artifacts.require("ClockMock.sol");

const ERC1400_TOKENS_VALIDATOR = "ERC1400TokensValidator";
const ERC1400_TOKENS_CHECKER = "ERC1400TokensChecker";

const ERC1400_TOKENS_SENDER = "ERC1400TokensSender";
const ERC1400_TOKENS_RECIPIENT = "ERC1400TokensRecipient";

const ERC1400TokensSender = artifacts.require("ERC1400TokensSenderMock");
const ERC1400TokensRecipient = artifacts.require("ERC1400TokensRecipientMock");

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_BYTE = "0x";

const EMPTY_BYTE32 =
  "0x0000000000000000000000000000000000000000000000000000000000000000";

const CERTIFICATE_SIGNER_PRIVATE_KEY = "0x1699611cc662aad2db30d5cf44bd531a8b16710e43624fc0e801c6592f72f9ab";
const CERTIFICATE_SIGNER = "0x2A3cE238F1903B1cA935D734e6160aBA029ff80a";

const EMPTY_CERTIFICATE = "0x";

const SALT_CERTIFICATE_WITH_V_EQUAL_TO_27 = "0xc146ced8f3786c604be1e79736551da9b9fbf013baa1db094ce9940a4ef5af4d000000000000000000000000000000000000000000000000000000005faf0d7a8a94cd85101a9285611e7bea0a6349497ffb9d25be95dee9e43af78437514a6c11d3525bb439dab160e3b7b1bf6fd3b35423d61533658759ceef0b5b019c29691b";
const SALT_CERTIFICATE_WITH_V_EQUAL_TO_28 = "0xc146ced8f3786c604be1e79736551da9b9fbf013baa1db094ce9940a4ef5af4d000000000000000000000000000000000000000000000000000000005faf0d7a8a94cd85101a9285611e7bea0a6349497ffb9d25be95dee9e43af78437514a6c11d3525bb439dab160e3b7b1bf6fd3b35423d61533658759ceef0b5b019c29691c";
const SALT_CERTIFICATE_WITH_V_EQUAL_TO_29 = "0xc146ced8f3786c604be1e79736551da9b9fbf013baa1db094ce9940a4ef5af4d000000000000000000000000000000000000000000000000000000005faf0d7a8a94cd85101a9285611e7bea0a6349497ffb9d25be95dee9e43af78437514a6c11d3525bb439dab160e3b7b1bf6fd3b35423d61533658759ceef0b5b019c29691d";

const NONCE_CERTIFICATE_WITH_V_EQUAL_TO_27 = "0x00000000000000000000000000000000000000000000000000000000c4427ed1057da68ae02a18da9be28448860b16d3903ff8476a2f86effbde677695466aa720f3a5c4f0e450403a66854ea20b7356fcff1cf100d291907ef6f9a6ac25f3a31b";
const NONCE_CERTIFICATE_WITH_V_EQUAL_TO_28 = "0x00000000000000000000000000000000000000000000000000000000c4427ed1057da68ae02a18da9be28448860b16d3903ff8476a2f86effbde677695466aa720f3a5c4f0e450403a66854ea20b7356fcff1cf100d291907ef6f9a6ac25f3a31c";
const NONCE_CERTIFICATE_WITH_V_EQUAL_TO_29 = "0x00000000000000000000000000000000000000000000000000000000c4427ed1057da68ae02a18da9be28448860b16d3903ff8476a2f86effbde677695466aa720f3a5c4f0e450403a66854ea20b7356fcff1cf100d291907ef6f9a6ac25f3a31d";

const CERTIFICATE_VALIDITY_PERIOD = 1; // Certificate will be valid for 1 hour

const INVALID_CERTIFICATE_SENDER =
  "0x1100000000000000000000000000000000000000000000000000000000000000";
const INVALID_CERTIFICATE_RECIPIENT =
  "0x2200000000000000000000000000000000000000000000000000000000000000";

const partition1_short =
  "5265736572766564000000000000000000000000000000000000000000000000"; // Reserved in hex
const partition2_short =
  "4973737565640000000000000000000000000000000000000000000000000000"; // Issued in hex
const partition3_short =
  "4c6f636b65640000000000000000000000000000000000000000000000000000"; // Locked in hex

const partition1 = "0x".concat(partition1_short);
const partition2 = "0x".concat(partition2_short);
const partition3 = "0x".concat(partition3_short);

const partitions = [partition1, partition2, partition3];

const partitionFlag =
  "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; // Flag to indicate a partition change
const changeToPartition1 = partitionFlag.concat(partition1_short);
const changeToPartition2 = partitionFlag.concat(partition2_short);
const changeToPartition3 = partitionFlag.concat(partition3_short);

const ESC_00 = "0x00"; // Transfer verifier not setup
const ESC_50 = "0x50"; // 0x50	transfer failure
const ESC_51 = "0x51"; // 0x51	transfer success
const ESC_52 = "0x52"; // 0x52	insufficient balance
// const ESC_53 = '0x53'; // 0x53	insufficient allowance
const ESC_54 = "0x54"; // 0x54	transfers halted (contract paused)
// const ESC_55 = '0x55'; // 0x55	funds locked (lockup period)
const ESC_56 = "0x56"; // 0x56	invalid sender
const ESC_57 = "0x57"; // 0x57	invalid receiver
const ESC_58 = "0x58"; // 0x58	invalid operator (transfer agent)

const issuanceAmount = 1000;
const holdAmount = 600;

const SECONDS_IN_AN_HOUR = 3600;
const SECONDS_IN_A_DAY = 24*SECONDS_IN_AN_HOUR;

const CERTIFICATE_VALIDATION_NONE = 0;
const CERTIFICATE_VALIDATION_NONCE = 1;
const CERTIFICATE_VALIDATION_SALT = 2;
const CERTIFICATE_VALIDATION_DEFAULT = CERTIFICATE_VALIDATION_SALT;

const numberToHexa = (num, pushTo) => {
  const arr1 = [];
  const str = num.toString(16);
  if(str.length%2 === 1) {
    arr1.push('0');
    pushTo -=1;
  }
  for (let m = str.length / 2; m < pushTo; m++) {
    arr1.push('0');
    arr1.push('0');
  }
  for (let n = 0, l = str.length; n < l; n++) {
    const hex = str.charAt(n);
    arr1.push(hex);
  }
  return arr1.join('');
};

const assertTotalSupply = async (_contract, _amount) => {
  totalSupply = await _contract.totalSupply();
  assert.equal(totalSupply, _amount);
};

const assertBalanceOf = async (
  _contract,
  _tokenHolder,
  _partition,
  _amount
) => {
  await assertBalance(_contract, _tokenHolder, _amount);
  await assertBalanceOfByPartition(
    _contract,
    _tokenHolder,
    _partition,
    _amount
  );
};

const assertBalanceOfByPartition = async (
  _contract,
  _tokenHolder,
  _partition,
  _amount
) => {
  balanceByPartition = await _contract.balanceOfByPartition(
    _partition,
    _tokenHolder
  );
  assert.equal(balanceByPartition, _amount);
};

const assertBalance = async (_contract, _tokenHolder, _amount) => {
  balance = await _contract.balanceOf(_tokenHolder);
  assert.equal(balance, _amount);
};

const assertEscResponse = async (
  _response,
  _escCode,
  _additionalCode,
  _destinationPartition
) => {
  assert.equal(_response[0], _escCode);
  assert.equal(_response[1], _additionalCode);
  assert.equal(_response[2], _destinationPartition);
};

const assertTokenHasExtension = async (
  _registry,
  _extension,
  _token,
) => {
  let extensionImplementer = await _registry.getInterfaceImplementer(
    _token.address,
    soliditySha3(ERC1400_TOKENS_VALIDATOR)
  );
  assert.equal(extensionImplementer, _extension.address);
}

const setNewExtensionForToken = async (
  _extension,
  _token,
  _sender,
) => {
  const controllers = await _token.controllers();
  await _extension.registerTokenSetup(
    _token.address,
    CERTIFICATE_VALIDATION_DEFAULT,
    true,
    true,
    true,
    true,
    controllers,
    { from: _sender }
  );

  await _token.setTokenExtension(
    _extension.address,
    ERC1400_TOKENS_VALIDATOR,
    true,
    true,
    true,
    { from: _sender }
  );
}

const assertCertificateActivated = async (
  _extension,
  _token,
  _expectedValue
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  assert.equal(_expectedValue, parseInt(tokenSetup[0]));
}

const setCertificateActivated = async (
  _extension,
  _token,
  _sender,
  _value
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  await _extension.registerTokenSetup(
    _token.address,
    _value,
    tokenSetup[1],
    tokenSetup[2],
    tokenSetup[3],
    tokenSetup[4],
    tokenSetup[5],
    { from: _sender }
  );
}

const assertAllowListActivated = async (
  _extension,
  _token,
  _expectedValue
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  assert.equal(_expectedValue, tokenSetup[1]);
}

const setAllowListActivated = async (
  _extension,
  _token,
  _sender,
  _value
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  await _extension.registerTokenSetup(
    _token.address,
    tokenSetup[0],
    _value,
    tokenSetup[2],
    tokenSetup[3],
    tokenSetup[4],
    tokenSetup[5],
    { from: _sender }
  );
}

const assertBlockListActivated = async (
  _extension,
  _token,
  _expectedValue
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  assert.equal(_expectedValue, tokenSetup[2]);
}

const setBlockListActivated = async (
  _extension,
  _token,
  _sender,
  _value
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  await _extension.registerTokenSetup(
    _token.address,
    tokenSetup[0],
    tokenSetup[1],
    _value,
    tokenSetup[3],
    tokenSetup[4],
    tokenSetup[5],
    { from: _sender }
  );
}

const assertTokensLimitActivated = async (
  _extension,
  _token,
  _expectedValue
) => {
  const customExtensionSetup = await _extension.retrieveCustomExtensionSetup(_token.address);
  assert.equal(_expectedValue, customExtensionSetup[0]);
}

const setTokensLimitActivated = async (
  _extension,
  _token,
  _sender,
  _value
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  const tokensLimitSetup = await _extension.retrieveCustomExtensionSetup(_token.address);
  await _extension.registerTokenSetup(
    _token.address,
    tokenSetup[0],
    tokenSetup[1],
    tokenSetup[2],
    tokenSetup[3],
    tokenSetup[4],
    tokenSetup[5],
    { from: _sender }
  );

  await _extension.registerCustomExtensionSetup(
    _token.address,
    _value,
    tokensLimitSetup[1],
    { from: _sender }
  );
}

const assertAccountLimitActivated = async (
  _extension,
  _token,
  _expectedValue
) => {
  const customExtensionSetup = await _extension.retrieveCustomExtensionSetup(_token.address);
  assert.equal(_expectedValue, customExtensionSetup[1]);
}

const setAccountLimitActivated = async (
  _extension,
  _token,
  _sender,
  _value
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  const tokensLimitSetup = await _extension.retrieveCustomExtensionSetup(_token.address);
  await _extension.registerTokenSetup(
    _token.address,
    tokenSetup[0],
    tokenSetup[1],
    tokenSetup[2],
    tokenSetup[3],
    tokenSetup[4],
    tokenSetup[5],
    { from: _sender }
  );

  await _extension.registerCustomExtensionSetup(
    _token.address,
    tokensLimitSetup[0],
    _value,
    { from: _sender }
  );
}

const assertGranularityByPartitionActivated = async (
  _extension,
  _token,
  _expectedValue
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  assert.equal(_expectedValue, tokenSetup[3]);
}

const setGranularityByPartitionActivated = async (
  _extension,
  _token,
  _sender,
  _value
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  await _extension.registerTokenSetup(
    _token.address,
    tokenSetup[0],
    tokenSetup[1],
    tokenSetup[2],
    _value,
    tokenSetup[4],
    tokenSetup[5],
    { from: _sender }
  );
}

const assertHoldsActivated = async (
  _extension,
  _token,
  _expectedValue
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  assert.equal(_expectedValue, tokenSetup[4]);
}

const setHoldsActivated = async (
  _extension,
  _token,
  _sender,
  _value
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  await _extension.registerTokenSetup(
    _token.address,
    tokenSetup[0],
    tokenSetup[1],
    tokenSetup[2],
    tokenSetup[3],
    _value,
    tokenSetup[5],
    { from: _sender }
  );
}

const assertIsTokenController = async (
  _extension,
  _token,
  _controller,
  _value,
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  const controllerList = tokenSetup[5];
  assert.equal(_value, controllerList.includes(_controller))
}

const addTokenController = async (
  _extension,
  _token,
  _sender,
  _newController
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  const controllerList = tokenSetup[5];
  if (!controllerList.includes(_newController)) {
    controllerList.push(_newController);
  }
  await _extension.registerTokenSetup(
    _token.address,
    tokenSetup[0],
    tokenSetup[1],
    tokenSetup[2],
    tokenSetup[3],
    tokenSetup[4],
    controllerList,
    { from: _sender }
  );
}

const craftCertificate = async (
  _txPayload,
  _token,
  _extension,
  _clock, // this.clock
  _txSender
) => {
  const tokenSetup = await _extension.retrieveTokenSetup(_token.address);
  if (parseInt(tokenSetup[0]) === CERTIFICATE_VALIDATION_NONCE) {
    return craftNonceBasedCertificate(
      _txPayload,
      _token,
      _extension,
      _clock, // this.clock
      _txSender
    );
  } else if (parseInt(tokenSetup[0]) === CERTIFICATE_VALIDATION_SALT) {
    return craftSaltBasedCertificate(
      _txPayload,
      _token,
      _extension,
      _clock,
      _txSender
    );
  } else {
    return EMPTY_CERTIFICATE;
  }
}

const craftNonceBasedCertificate = async (
  _txPayload,
  _token,
  _extension,
  _clock, // this.clock
  _txSender
) => {
  // Retrieve current nonce from smart contract
  const nonce = await _extension.usedCertificateNonce(_token.address, _txSender);

  const time = await _clock.getTime();
  const expirationTime = new Date(1000*(parseInt(time) + CERTIFICATE_VALIDITY_PERIOD * SECONDS_IN_AN_HOUR));
  const expirationTimeAsNumber = Math.floor(
    expirationTime.getTime() / 1000,
  );

  let rawTxPayload;
  if (_txPayload.length >= 64) {
    rawTxPayload = _txPayload.substring(0, _txPayload.length - 64);
  } else {
    throw new Error(
      `txPayload shall be at least 32 bytes long (${
        _txPayload.length / 2
      } instead)`,
    );
  }

  const packedAndHashedParameters = soliditySha3(
    { type: 'address', value: _txSender.toString() },
    { type: 'address', value: _token.address.toString() },
    { type: 'bytes', value: rawTxPayload },
    { type: 'uint256', value: expirationTimeAsNumber.toString() },
    { type: 'uint256', value: nonce.toString()  },
  );

  const signature = Account.sign(
    packedAndHashedParameters,
    CERTIFICATE_SIGNER_PRIVATE_KEY,
  );
  const vrs = Account.decodeSignature(signature);
  const v = vrs[0].substring(2).replace('1b', '00').replace('1c', '01');
  const r = vrs[1].substring(2);
  const s = vrs[2].substring(2);

  const certificate = `0x${numberToHexa(expirationTimeAsNumber,32)}${r}${s}${v}`;

  return certificate;

}

const craftSaltBasedCertificate = async (
  _txPayload,
  _token,
  _extension,
  _clock, // this.clock
  _txSender
) => {
  // Generate a random salt, which has never been used before
  const salt = soliditySha3(new Date().getTime().toString());

  // Check if salt has already been used, even though that very un likely to happen (statistically impossible)
  const saltHasAlreadyBeenUsed = await _extension.usedCertificateSalt(_token.address, salt);

  if (saltHasAlreadyBeenUsed) {
    throw new Error('can never happen: salt has already been used (statistically impossible)');
  }

  const time = await _clock.getTime();
  const expirationTime = new Date(1000*(parseInt(time) + CERTIFICATE_VALIDITY_PERIOD * 3600));
  const expirationTimeAsNumber = Math.floor(
    expirationTime.getTime() / 1000,
  );

  let rawTxPayload;
  if (_txPayload.length >= 64) {
    rawTxPayload = _txPayload.substring(0, _txPayload.length - 64);
  } else {
    throw new Error(
      `txPayload shall be at least 32 bytes long (${
        _txPayload.length / 2
      } instead)`,
    );
  }

  const packedAndHashedParameters = soliditySha3(
    { type: 'address', value: _txSender.toString() },
    { type: 'address', value: _token.address.toString() },
    { type: 'bytes', value: rawTxPayload },
    { type: 'uint256', value: expirationTimeAsNumber.toString() },
    { type: 'bytes32', value: salt.toString() },
  );

  const signature = Account.sign(
    packedAndHashedParameters,
    CERTIFICATE_SIGNER_PRIVATE_KEY,
  );
  const vrs = Account.decodeSignature(signature);
  const v = vrs[0].substring(2).replace('1b', '00').replace('1c', '01');
  const r = vrs[1].substring(2);
  const s = vrs[2].substring(2);

  const certificate = `0x${salt.substring(2)}${numberToHexa(
    expirationTimeAsNumber,
    32,
  )}${r}${s}${v}`;

  return certificate;

}

contract("ERC1400HoldableCertificate with token extension", function ([
  deployer,
  owner,
  operator,
  controller,
  tokenHolder,
  recipient,
  notary,
  unknown,
  tokenController1,
  tokenController2
]) {
  before(async function () {
    this.registry = await ERC1820Registry.at(
      "0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24"
    );

    this.clock = await ClockMock.new();

    this.extension = await ERC1400TokensValidator.new({
      from: deployer,
    });
  });

  beforeEach(async function () {
    this.token = await ERC1400HoldableCertificate.new(
      "ERC1400Token",
      "DAU",
      1,
      [controller],
      partitions,
      this.extension.address,
      owner,
      CERTIFICATE_SIGNER,
      CERTIFICATE_VALIDATION_DEFAULT,
      { from: controller }
    );
  });

  // MOCK
  describe("setTokenExtension", function () {
    it("mock to test modifiers of roles functions", async function () {
      await FakeERC1400Mock.new(
        "ERC1400Token",
        "DAU",
        1,
        [controller],
        partitions,
        this.extension.address,
        owner,
        { from: controller }
      );
    });
  });

  // SET TOKEN EXTENSION
  describe("setTokenExtension", function () {
    describe("when the caller is the contract owner", function () {
      describe("when the the validator contract is not already a minter", function () {
        describe("when there is was no previous validator contract", function () {
          it("sets the token extension", async function () {
            this.token = await ERC1400HoldableCertificate.new(
              "ERC1400Token",
              "DAU",
              1,
              [controller],
              partitions,
              ZERO_ADDRESS,
              owner,
              ZERO_ADDRESS,
              CERTIFICATE_VALIDATION_DEFAULT,
              { from: controller }
            );

            assert.equal(await this.token.owner(), owner)

            let extensionImplementer = await this.registry.getInterfaceImplementer(
              this.token.address,
              soliditySha3(ERC1400_TOKENS_VALIDATOR)
            );
            assert.equal(extensionImplementer, ZERO_ADDRESS);
            assert.equal(await this.token.isOperator(this.extension.address, unknown), false)
            assert.equal(await this.token.isMinter(this.extension.address), false)
    
            await this.token.setTokenExtension(
              this.extension.address,
              ERC1400_TOKENS_VALIDATOR,
              true,
              true,
              true,
              { from: owner }
            );
    
            extensionImplementer = await this.registry.getInterfaceImplementer(
              this.token.address,
              soliditySha3(ERC1400_TOKENS_VALIDATOR)
            );
            assert.equal(extensionImplementer, this.extension.address);
            assert.equal(await this.token.isOperator(this.extension.address, unknown), true)
            assert.equal(await this.token.isMinter(this.extension.address), true)
          });
        });
        describe("when there is was a previous validator contract", function () {
          describe("when the previous validator contract was a minter", function () {
            it("sets the token extension (with controller and minter rights)", async function () {
              assert.equal(await this.token.owner(), owner)

              await assertTokenHasExtension(
                this.registry,
                this.extension,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.extension.address, unknown), true)
              assert.equal(await this.token.isMinter(this.extension.address), true)
  
              this.validatorContract2 = await ERC1400TokensValidator.new({
                from: deployer,
              });
      
              await this.token.setTokenExtension(
                this.validatorContract2.address,
                ERC1400_TOKENS_VALIDATOR,
                true,
                true,
                true,
                { from: owner }
              );
      
              await assertTokenHasExtension(
                this.registry,
                this.validatorContract2,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.validatorContract2.address, unknown), true)
              assert.equal(await this.token.isMinter(this.validatorContract2.address), true)
  
              assert.equal(await this.token.isOperator(this.extension.address, unknown), false)
              assert.equal(await this.token.isMinter(this.extension.address), false)
            });
            it("sets the token extension (without controller rights)", async function () {
              assert.equal(await this.token.owner(), owner)

              await assertTokenHasExtension(
                this.registry,
                this.extension,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.extension.address, unknown), true)
              assert.equal(await this.token.isMinter(this.extension.address), true)
  
              this.validatorContract2 = await ERC1400TokensValidator.new({
                from: deployer,
              });
      
              await this.token.setTokenExtension(
                this.validatorContract2.address,
                ERC1400_TOKENS_VALIDATOR,
                true,
                true,
                false,
                { from: owner }
              );
      
              await assertTokenHasExtension(
                this.registry,
                this.validatorContract2,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.validatorContract2.address, unknown), false)
              assert.equal(await this.token.isMinter(this.validatorContract2.address), true)
  
              assert.equal(await this.token.isOperator(this.extension.address, unknown), false)
              assert.equal(await this.token.isMinter(this.extension.address), false)
            });
            it("sets the token extension (without minter rights)", async function () {
              assert.equal(await this.token.owner(), owner)

              await assertTokenHasExtension(
                this.registry,
                this.extension,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.extension.address, unknown), true)
              assert.equal(await this.token.isMinter(this.extension.address), true)
  
              this.validatorContract2 = await ERC1400TokensValidator.new({
                from: deployer,
              });
      
              await this.token.setTokenExtension(
                this.validatorContract2.address,
                ERC1400_TOKENS_VALIDATOR,
                true,
                false,
                true,
                { from: owner }
              );
      
              await assertTokenHasExtension(
                this.registry,
                this.validatorContract2,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.validatorContract2.address, unknown), true)
              assert.equal(await this.token.isMinter(this.validatorContract2.address), false)
  
              assert.equal(await this.token.isOperator(this.extension.address, unknown), false)
              assert.equal(await this.token.isMinter(this.extension.address), false)
            });
            it("sets the token extension (while leaving minter and controller rights to the old extension)", async function () {
              assert.equal(await this.token.owner(), owner)

              await assertTokenHasExtension(
                this.registry,
                this.extension,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.extension.address, unknown), true)
              assert.equal(await this.token.isMinter(this.extension.address), true)
  
              this.validatorContract2 = await ERC1400TokensValidator.new({
                from: deployer,
              });
      
              await this.token.setTokenExtension(
                this.validatorContract2.address,
                ERC1400_TOKENS_VALIDATOR,
                false,
                true,
                true,
                { from: owner }
              );
      
              await assertTokenHasExtension(
                this.registry,
                this.validatorContract2,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.validatorContract2.address, unknown), true)
              assert.equal(await this.token.isMinter(this.validatorContract2.address), true)
  
              assert.equal(await this.token.isOperator(this.extension.address, unknown), true)
              assert.equal(await this.token.isMinter(this.extension.address), true)
            });
          });
          describe("when the previous validator contract was not a minter", function () {
            it("sets the token extension", async function () {  
              this.validatorContract2 = await ERC1400TokensValidatorMock.new({
                from: deployer,
              });
      
              await this.token.setTokenExtension(
                this.validatorContract2.address,
                ERC1400_TOKENS_VALIDATOR,
                true,
                true,
                true,
                { from: owner }
              );
      
              await assertTokenHasExtension(
                this.registry,
                this.validatorContract2,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.validatorContract2.address, unknown), true)
              assert.equal(await this.token.isMinter(this.validatorContract2.address), true)

              await this.validatorContract2.renounceMinter(this.token.address, { from: owner });

              assert.equal(await this.token.isOperator(this.validatorContract2.address, unknown), true)
              assert.equal(await this.token.isMinter(this.validatorContract2.address), false)
      
              await this.token.setTokenExtension(
                this.extension.address,
                ERC1400_TOKENS_VALIDATOR,
                true,
                true,
                true,
                { from: owner }
              );

              assert.equal(await this.token.isOperator(this.validatorContract2.address, unknown), false)
              assert.equal(await this.token.isMinter(this.validatorContract2.address), false)
      
              await assertTokenHasExtension(
                this.registry,
                this.extension,
                this.token,
              );
              assert.equal(await this.token.isOperator(this.extension.address, unknown), true)
              assert.equal(await this.token.isMinter(this.extension.address), true)
            });
          });
        });
      });
      describe("when the the validator contract is already a minter", function () {
        it("sets the token extension", async function () {
          this.validatorContract2 = await ERC1400TokensValidatorMock.new({
            from: deployer,
          });

          await assertTokenHasExtension(
            this.registry,
            this.extension,
            this.token,
          );

          await this.token.addMinter(this.validatorContract2.address, { from: controller });

          assert.equal(await this.token.isOperator(this.validatorContract2.address, unknown), false)
          assert.equal(await this.token.isMinter(this.validatorContract2.address), true)
  
          await this.token.setTokenExtension(
            this.validatorContract2.address,
            ERC1400_TOKENS_VALIDATOR,
            true,
            true,
            true,
            { from: owner }
          );
  
          await assertTokenHasExtension(
            this.registry,
            this.validatorContract2,
            this.token,
          );
          assert.equal(await this.token.isOperator(this.validatorContract2.address, unknown), true)
          assert.equal(await this.token.isMinter(this.validatorContract2.address), true)
        });
      });
    });
    describe("when the caller is not the contract owner", function () {
      it("reverts", async function () {
        this.validatorContract2 = await ERC1400TokensValidator.new({
          from: deployer,
        });
        await expectRevert.unspecified(
          this.token.setTokenExtension(
            this.validatorContract2.address,
            ERC1400_TOKENS_VALIDATOR,
            true,
            true,
            true,
            { from: controller }
          )
        );
      });
    });
  });

  // CERTIFICATE SIGNER
  describe("certificate signer role", function () {
    describe("addCertificateSigner/removeCertificateSigner", function () {
      beforeEach(async function () {
        await assertTokenHasExtension(
          this.registry,
          this.extension,
          this.token,
        );
      });
      describe("add/renounce a certificate signer", function () {
        describe("when caller is a certificate signer", function () {
          it("adds a certificate signer as owner", async function () {
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
            await this.extension.addCertificateSigner(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              true
            );
          });
          it("adds a certificate signer as token controller", async function () {
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
            await this.extension.addCertificateSigner(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              true
            );
          });
          it("adds a certificate signer as certificate signer", async function () {
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
            await this.extension.addCertificateSigner(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              true
            );
  
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, tokenHolder),
              false
            );
            await this.extension.addCertificateSigner(this.token.address, tokenHolder, {
              from: unknown,
            });
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, tokenHolder),
              true
            );
          });
          it("renounces certificate signer", async function () {
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
            await this.extension.addCertificateSigner(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              true
            );
            await this.extension.renounceCertificateSigner(this.token.address, {
              from: unknown,
            });
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
          });
        });
        describe("when caller is not a certificate signer", function () {
          it("reverts", async function () {
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
            await expectRevert.unspecified(
              this.extension.addCertificateSigner(this.token.address, unknown, { from: unknown })
            );
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
          });
        });
      });
      describe("remove a certificate signer", function () {
        describe("when caller is a certificate signer", function () {
          it("removes a certificate signer as owner", async function () {
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
            await this.extension.addCertificateSigner(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              true
            );
            await this.extension.removeCertificateSigner(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
          });
        });
        describe("when caller is not a certificate signer", function () {
          it("reverts", async function () {
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              false
            );
            await this.extension.addCertificateSigner(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              true
            );
            await expectRevert.unspecified(this.extension.removeCertificateSigner(this.token.address, unknown, {
              from: tokenHolder,
            }));
            assert.equal(
              await this.extension.isCertificateSigner(this.token.address, unknown),
              true
            );
          });
        });
      });
    });
    describe("case where certificate is not defined at creation [for coverage]", function () {
      describe("can not call function if not certificate signer", function () {
        it("creates the token", async function () {
          await ERC1400HoldableCertificate.new(
            "ERC1400Token",
            "DAU",
            1,
            [controller],
            partitions,
            this.extension.address,
            owner,
            ZERO_ADDRESS, // <-- certificate signer is not defined
            CERTIFICATE_VALIDATION_DEFAULT,
            { from: controller }
          );
        });
      });
    });
    describe("onlyCertificateSigner [mock for coverage]", function () {
      beforeEach(async function () {
        this.certificateSignerMock = await CertificateSignerMock.new(this.token.address, { from: owner });
      });
      describe("can not call function if not certificate signer", function () {
        it("reverts", async function () {
          assert.equal(await this.certificateSignerMock.isCertificateSigner(this.token.address, unknown), false);
          await expectRevert.unspecified(
            this.certificateSignerMock.addCertificateSigner(this.token.address, unknown, { from: unknown })
          );
          assert.equal(await this.certificateSignerMock.isCertificateSigner(this.token.address, unknown), false);
          await this.certificateSignerMock.addCertificateSigner(this.token.address, unknown, { from: owner })
          assert.equal(await this.certificateSignerMock.isCertificateSigner(this.token.address, unknown), true);
        });
      });
    });
  });
  
  // ALLOWLIST ADMIN
  describe("allowlist admin role", function () {
    describe("addAllowlisted/removeAllowlistAdmin", function () {
      beforeEach(async function () {
        await assertTokenHasExtension(
          this.registry,
          this.extension,
          this.token,
        );
  
        await this.extension.addAllowlisted(this.token.address, tokenHolder, { from: controller });
        await this.extension.addAllowlisted(this.token.address, recipient, { from: controller });
        assert.equal(await this.extension.isAllowlisted(this.token.address, tokenHolder), true);
        assert.equal(await this.extension.isAllowlisted(this.token.address, recipient), true);
      });
      describe("add/renounce a allowlist admin", function () {
        describe("when caller is a allowlist admin", function () {
          it("adds a allowlist admin as owner", async function () {
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addAllowlistAdmin(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              true
            );
          });
          it("adds a allowlist admin as token controller", async function () {
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addAllowlistAdmin(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              true
            );
          });
          it("adds a allowlist admin as allowlist admin", async function () {
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addAllowlistAdmin(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              true
            );
  
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, tokenHolder),
              false
            );
            await this.extension.addAllowlistAdmin(this.token.address, tokenHolder, {
              from: unknown,
            });
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, tokenHolder),
              true
            );
          });
          it("renounces allowlist admin", async function () {
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addAllowlistAdmin(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              true
            );
            await this.extension.renounceAllowlistAdmin(this.token.address, {
              from: unknown,
            });
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
          });
        });
        describe("when caller is not a allowlist admin", function () {
          it("reverts", async function () {
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
            await expectRevert.unspecified(
              this.extension.addAllowlistAdmin(this.token.address, unknown, { from: unknown })
            );
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
          });
        });
      });
      describe("remove a allowlist admin", function () {
        describe("when caller is a allowlist admin", function () {
          it("removes a allowlist admin as owner", async function () {
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addAllowlistAdmin(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              true
            );
            await this.extension.removeAllowlistAdmin(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
          });
        });
        describe("when caller is not a allowlist admin", function () {
          it("reverts", async function () {
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addAllowlistAdmin(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              true
            );
            await expectRevert.unspecified(this.extension.removeAllowlistAdmin(this.token.address, unknown, {
              from: tokenHolder,
            }));
            assert.equal(
              await this.extension.isAllowlistAdmin(this.token.address, unknown),
              true
            );
          });
        });
      });
    });
    describe("onlyNotAllowlisted [mock for coverage]", function () {
      beforeEach(async function () {
        this.allowlistMock = await AllowlistMock.new(this.token.address, { from: owner });
      });
      describe("can not call function if allowlisted", function () {
        it("reverts", async function () {
          assert.equal(await this.allowlistMock.isAllowlisted(this.token.address, unknown), false);
          await this.allowlistMock.mockFunction(this.token.address, true, { from: unknown });
          await this.allowlistMock.addAllowlisted(this.token.address, unknown, { from: owner });
          assert.equal(await this.allowlistMock.isAllowlisted(this.token.address, unknown), true);
  
          await expectRevert.unspecified(
            this.allowlistMock.mockFunction(this.token.address, true, { from: unknown })
          );
        });
      });
    });
    describe("onlyAllowlistAdmin [mock for coverage]", function () {
      beforeEach(async function () {
        this.allowlistMock = await AllowlistMock.new(this.token.address, { from: owner });
      });
      describe("can not call function if not allowlist admin", function () {
        it("reverts", async function () {
          assert.equal(await this.allowlistMock.isAllowlistAdmin(this.token.address, unknown), false);
          await expectRevert.unspecified(
            this.allowlistMock.addAllowlistAdmin(this.token.address, unknown, { from: unknown })
          );
          assert.equal(await this.allowlistMock.isAllowlistAdmin(this.token.address, unknown), false);
          await this.allowlistMock.addAllowlistAdmin(this.token.address, unknown, { from: owner })
          assert.equal(await this.allowlistMock.isAllowlistAdmin(this.token.address, unknown), true);
        });
      });
    });
    
  });

  // BLOCKLIST ADMIN
  describe("blocklist admin role", function () {
    describe("addBlocklisted/removeBlocklistAdmin", function () {
      beforeEach(async function () {
        await assertTokenHasExtension(
          this.registry,
          this.extension,
          this.token,
        );
  
        await this.extension.addBlocklisted(this.token.address, tokenHolder, { from: controller });
        await this.extension.addBlocklisted(this.token.address, recipient, { from: controller });
        assert.equal(await this.extension.isBlocklisted(this.token.address, tokenHolder), true);
        assert.equal(await this.extension.isBlocklisted(this.token.address, recipient), true);
      });
      describe("add/renounce a blocklist admin", function () {
        describe("when caller is a blocklist admin", function () {
          it("adds a blocklist admin as owner", async function () {
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addBlocklistAdmin(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              true
            );
          });
          it("adds a blocklist admin as token controller", async function () {
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addBlocklistAdmin(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              true
            );
          });
          it("adds a blocklist admin as blocklist admin", async function () {
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addBlocklistAdmin(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              true
            );
  
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, tokenHolder),
              false
            );
            await this.extension.addBlocklistAdmin(this.token.address, tokenHolder, {
              from: unknown,
            });
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, tokenHolder),
              true
            );
          });
          it("renounces blocklist admin", async function () {
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addBlocklistAdmin(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              true
            );
            await this.extension.renounceBlocklistAdmin(this.token.address, {
              from: unknown,
            });
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
          });
        });
        describe("when caller is not a blocklist admin", function () {
          it("reverts", async function () {
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
            await expectRevert.unspecified(
              this.extension.addBlocklistAdmin(this.token.address, unknown, { from: unknown })
            );
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
          });
        });
      });
      describe("remove a blocklist admin", function () {
        describe("when caller is a blocklist admin", function () {
          it("removes a blocklist admin as owner", async function () {
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addBlocklistAdmin(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              true
            );
            await this.extension.removeBlocklistAdmin(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
          });
        });
        describe("when caller is not a blocklist admin", function () {
          it("reverts", async function () {
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              false
            );
            await this.extension.addBlocklistAdmin(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              true
            );
            await expectRevert.unspecified(this.extension.removeBlocklistAdmin(this.token.address, unknown, {
              from: tokenHolder,
            }));
            assert.equal(
              await this.extension.isBlocklistAdmin(this.token.address, unknown),
              true
            );
          });
        });
      });
    });
    describe("onlyNotBlocklisted [mock for coverage]", function () {
      beforeEach(async function () {
        this.blocklistMock = await BlocklistMock.new(this.token.address, { from: owner });
      });
      describe("can not call function if blocklisted", function () {
        it("reverts", async function () {
          assert.equal(await this.blocklistMock.isBlocklisted(this.token.address, unknown), false);
          await this.blocklistMock.mockFunction(this.token.address, true, { from: unknown });
          await this.blocklistMock.addBlocklisted(this.token.address, unknown, { from: owner });
          assert.equal(await this.blocklistMock.isBlocklisted(this.token.address, unknown), true);
  
          await expectRevert.unspecified(
            this.blocklistMock.mockFunction(this.token.address, true, { from: unknown })
          );
        });
      });
    });
    describe("onlyBlocklistAdmin [mock for coverage]", function () {
      beforeEach(async function () {
        this.blocklistMock = await BlocklistMock.new(this.token.address, { from: owner });
      });
      describe("can not call function if not blocklist admin", function () {
        it("reverts", async function () {
          assert.equal(await this.blocklistMock.isBlocklistAdmin(this.token.address, unknown), false);
          await expectRevert.unspecified(
            this.blocklistMock.addBlocklistAdmin(this.token.address, unknown, { from: unknown })
          );
          assert.equal(await this.blocklistMock.isBlocklistAdmin(this.token.address, unknown), false);
          await this.blocklistMock.addBlocklistAdmin(this.token.address, unknown, { from: owner })
          assert.equal(await this.blocklistMock.isBlocklistAdmin(this.token.address, unknown), true);
        });
      });
    });
  
  });

  // PAUSER
  describe("pauser role", function () {
    describe("addPauser/removePauser", function () {
      beforeEach(async function () {
        await assertTokenHasExtension(
          this.registry,
          this.extension,
          this.token,
        );
  
      });
      describe("add/renounce a pauser", function () {
        describe("when caller is a pauser", function () {
          it("adds a pauser as token owner", async function () {
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
            await this.extension.addPauser(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              true
            );
          });
          it("adds a pauser as token controller", async function () {
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
            await this.extension.addPauser(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              true
            );
          });
          it("adds a pauser as pauser", async function () {
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
            await this.extension.addPauser(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              true
            );
  
            assert.equal(
              await this.extension.isPauser(this.token.address, tokenHolder),
              false
            );
            await this.extension.addPauser(this.token.address, tokenHolder, {
              from: unknown,
            });
            assert.equal(
              await this.extension.isPauser(this.token.address, tokenHolder),
              true
            );
          });
          it("renounces pauser", async function () {
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
            await this.extension.addPauser(this.token.address, unknown, {
              from: controller,
            });
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              true
            );
            await this.extension.renouncePauser(this.token.address, {
              from: unknown,
            });
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
          });
        });
        describe("when caller is not a pauser", function () {
          it("reverts", async function () {
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
            await expectRevert.unspecified(
              this.extension.addPauser(this.token.address, unknown, { from: unknown })
            );
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
          });
        });
      });
      describe("remove a pauser", function () {
        describe("when caller is a pauser", function () {
          it("adds a pauser as token owner", async function () {
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
            await this.extension.addPauser(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              true
            );
            await this.extension.removePauser(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
          });
        });
        describe("when caller is not a pauser", function () {
          it("reverts", async function () {
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              false
            );
            await this.extension.addPauser(this.token.address, unknown, {
              from: owner,
            });
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              true
            );
            await expectRevert.unspecified(this.extension.removePauser(this.token.address, unknown, {
              from: tokenHolder,
            }));
            assert.equal(
              await this.extension.isPauser(this.token.address, unknown),
              true
            );
          });
        });
      });
    });
    describe("onlyPauser [mock for coverage]", function () {
      beforeEach(async function () {
        this.pauserMock = await PauserMock.new(this.token.address, { from: owner });
      });
      describe("can not call function if pauser", function () {
        it("reverts", async function () {
          assert.equal(await this.pauserMock.isPauser(this.token.address, unknown), false);
          await expectRevert.unspecified(
            this.pauserMock.mockFunction(this.token.address, true, { from: unknown })
          );
          await this.pauserMock.addPauser(this.token.address, unknown, { from: owner });
          assert.equal(await this.pauserMock.isPauser(this.token.address, unknown), true);
  
          await this.pauserMock.mockFunction(this.token.address, true, { from: unknown });
        });
      });
    });
  
  });

  // CERTIFICATE ACTIVATED
  describe("setCertificateActivated", function () {
    beforeEach(async function () {
      await assertTokenHasExtension(
        this.registry,
        this.extension,
        this.token,
      );
    });
    describe("when the caller is the contract owner", function () {
      it("activates the certificate", async function () {
        await assertCertificateActivated(
          this.extension,
          this.token,
          CERTIFICATE_VALIDATION_SALT
        );

        await setCertificateActivated(
          this.extension,
          this.token,
          controller,
          CERTIFICATE_VALIDATION_NONCE
        );

        await assertCertificateActivated(
          this.extension,
          this.token,
          CERTIFICATE_VALIDATION_NONCE
        )

        await setCertificateActivated(
          this.extension,
          this.token,
          controller,
          CERTIFICATE_VALIDATION_NONE
        );

        await assertCertificateActivated(
          this.extension,
          this.token,
          CERTIFICATE_VALIDATION_NONE
        )
      });
    });
    describe("when the caller is not the contract owner", function () {
      it("reverts", async function () {
        await expectRevert.unspecified(
          setAllowListActivated(
            this.extension,
            this.token,
            unknown,
            CERTIFICATE_VALIDATION_NONCE
          )
        );
      });
    });
  });

  // ALLOWLIST ACTIVATED
  describe("setAllowlistActivated", function () {
    beforeEach(async function () {
      await assertTokenHasExtension(
        this.registry,
        this.extension,
        this.token,
      );
    });
    describe("when the caller is the contract owner", function () {
      it("activates the allowlist", async function () {
        await assertAllowListActivated(
          this.extension,
          this.token,
          true
        );

        await setAllowListActivated(
          this.extension,
          this.token,
          controller,
          false
        );

        await assertAllowListActivated(
          this.extension,
          this.token,
          false
        )
      });
    });
    describe("when the caller is not the contract owner", function () {
      it("reverts", async function () {
        await expectRevert.unspecified(
          setAllowListActivated(
            this.extension,
            this.token,
            unknown,
            false
          )
        );
      });
    });
  });

  // BLOCKLIST ACTIVATED
  describe("setBlocklistActivated", function () {
    beforeEach(async function () {
      await assertTokenHasExtension(
        this.registry,
        this.extension,
        this.token,
      );
    });
    describe("when the caller is the contract owner", function () {
      it("activates the blocklist", async function () {
        await assertBlockListActivated(
          this.extension,
          this.token,
          true
        );

        await setBlockListActivated(
          this.extension,
          this.token,
          controller,
          false
        );

        await assertBlockListActivated(
          this.extension,
          this.token,
          false
        )
      });
    });
    describe("when the caller is not the contract owner", function () {
      it("reverts", async function () {
        await expectRevert.unspecified(
          setBlockListActivated(
            this.extension,
            this.token,
            unknown,
            false
          )
        );
      });
    });
  });

  /// TRANSACTION LIMIT EXTENSION
  describe("tokens transaction limit", function () {
    const transactionLimit = 10;
    beforeEach(async function () {
      await this.extension.addTokenLimitAdmin(this.token.address, controller, {
        from: owner,
      });

      const certificate = await craftCertificate(
        this.token.contract.methods.issueByPartition(
          partition1,
          tokenHolder,
          issuanceAmount,
          EMPTY_CERTIFICATE,
        ).encodeABI(),
        this.token,
        this.extension,
        this.clock, // this.clock
        controller
      );

      await this.token.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        certificate,
        { from: controller }
      );

      await setAllowListActivated(
        this.extension,
        this.token,
        controller,
        false
      );
      await assertAllowListActivated(
        this.extension,
        this.token,
        false
      );

      await setBlockListActivated(
        this.extension,
        this.token,
        controller,
        false
      )
      await assertBlockListActivated(
        this.extension,
        this.token,
        false
      );

      await setTokensLimitActivated(
        this.extension,
        this.token,
        controller,
        true
      )
      await assertTokensLimitActivated(
        this.extension,
        this.token,
        true
      );
    });

    describe("add tokens transaction limit", function () {
      beforeEach(async function () {
        await this.extension.addTransactionLimit(this.token.address, tokenHolder, transactionLimit, {
          from: controller,
        });
        const maxTransactionLimit = await this.extension.getTransactionLimit(this.token.address, tokenHolder);
        assert.equal(transactionLimit, maxTransactionLimit);
      });

      it("transfer the requested amount, when amount is less than transaction limit", async function () {
        await this.token.transfer(recipient, transactionLimit, { from: tokenHolder });
        await assertBalance(this.token, tokenHolder, issuanceAmount - transactionLimit);
        await assertBalance(this.token, recipient, transactionLimit);
      });

      it("revert the transfer amount, when requested amount is more than transaction limit", async function () {
        await expectRevert.unspecified(
          this.token.transfer(recipient, (transactionLimit + 1), { from: tokenHolder })
        );
        await assertBalance(this.token, tokenHolder, issuanceAmount);
        await assertBalance(this.token, recipient, 0);
      });
    });

    describe("remove tokens transaction limit", function () {
      beforeEach(async function () {
        await this.extension.removeTransactionLimit(this.token.address, tokenHolder, {
          from: controller,
        });
        const maxTransLimit = await this.extension.getTransactionLimit(this.token.address, tokenHolder);
        assert.equal(0, maxTransLimit);
      });

      it("transfer the transaction limit plus one, when transaction limit is removed", async function () {
        const limitPlusOne = transactionLimit + 1;
        await this.token.transfer(recipient, limitPlusOne, { from: tokenHolder });
        await assertBalance(this.token, tokenHolder, issuanceAmount - limitPlusOne);
        await assertBalance(this.token, recipient, limitPlusOne);
      });
    });
  });

  describe("tokens limit admin", function () {
    it("add admin to the token contract and verify admin mapped to the token", async function () {
      await this.extension.addTokenLimitAdmin(this.token.address, tokenHolder, {
        from: controller,
      });
      const isAdmin = await this.extension.isTokenLimitAdmin(this.token.address, tokenHolder);
      assert.equal(true, isAdmin);
    });

    it("remove admin from the token contract and verify admin is renounced from the token", async function () {
      await this.extension.addTokenLimitAdmin(this.token.address, tokenHolder, {
        from: controller,
      });
      const isAdmin = await this.extension.isTokenLimitAdmin(this.token.address, tokenHolder);
      assert.equal(true, isAdmin);

      await this.extension.renounceTokenLimitAdmin(this.token.address, tokenHolder, {
        from: controller,
      });
      const isTokensAdmin = await this.extension.isTokenLimitAdmin(this.token.address, tokenHolder);
      assert.equal(false, isTokensAdmin);
    });
  });

  /// ACCOUNT LIMIT EXTENSION
  describe("tokens account limit", function () {
    const accountLimit = 10;
    beforeEach(async function () {
      await this.extension.addTokenLimitAdmin(this.token.address, controller, {
        from: owner,
      });

      const certificate = await craftCertificate(
        this.token.contract.methods.issueByPartition(
          partition1,
          tokenHolder,
          issuanceAmount,
          EMPTY_CERTIFICATE,
        ).encodeABI(),
        this.token,
        this.extension,
        this.clock, // this.clock
        controller
      );
      await this.token.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        certificate,
        { from: controller }
      );

      await setAllowListActivated(
        this.extension,
        this.token,
        controller,
        false
      )
      await assertAllowListActivated(
        this.extension,
        this.token,
        false
      );

      await setBlockListActivated(
        this.extension,
        this.token,
        controller,
        false
      )
      await assertBlockListActivated(
        this.extension,
        this.token,
        false
      );

      await setAccountLimitActivated(
        this.extension,
        this.token,
        controller,
        true
      );

      await assertAccountLimitActivated(
        this.extension,
        this.token,
        true
      );
    });

    describe("add tokens account limit", function () {
      beforeEach(async function () {
        await this.extension.addAccountLimit(this.token.address, recipient, accountLimit, {
          from: controller,
        });
        const maxAccountLimit = await this.extension.getMaxAccountBalane(this.token.address, recipient);
        assert.equal(accountLimit, maxAccountLimit);
      });

      it("transfer the requested amount, when amount is less than account limit", async function () {
        await this.token.transfer(recipient, 5, { from: tokenHolder });
        await this.token.transfer(recipient, 5, { from: tokenHolder });
        await assertBalance(this.token, tokenHolder, issuanceAmount - 10);
        await assertBalance(this.token, recipient, 10);
      });

      it("revert the transfer amount, when requested amount is more than account limit", async function () {
        await this.token.transfer(recipient, 5, { from: tokenHolder });
        await this.token.transfer(recipient, 5, { from: tokenHolder });
        await expectRevert.unspecified(
          this.token.transfer(recipient, 2, { from: tokenHolder })
        );
        await assertBalance(this.token, tokenHolder, issuanceAmount - 10);
        await assertBalance(this.token, recipient, 10);
      });
    });

    describe("remove tokens account limit", function () {
      beforeEach(async function () {
        await this.extension.removeAccountLimit(this.token.address, recipient, {
          from: controller,
        });
        const maxAccountLimit = await this.extension.getMaxAccountBalane(this.token.address, recipient);
        assert.equal(0, maxAccountLimit);
      });

      it("transfer the account limit plus one, when account limit is removed", async function () {
        await this.token.transfer(recipient, 5, { from: tokenHolder });
        await this.token.transfer(recipient, 6, { from: tokenHolder });
        assert.isAbove((5 + 6), accountLimit);
        await assertBalance(this.token, tokenHolder, issuanceAmount - 11);
        await assertBalance(this.token, recipient, 11);
      });
    });
  });

  // PARTITION EXPIRY
  describe("partition-expiry", function () {
    beforeEach(async function () {
      const time = parseInt(await this.clock.getTime());
      this.validTimestamp = time+SECONDS_IN_AN_HOUR;
      this.invalidTimestamp = time-1;

      const certificate = await craftCertificate(
        this.token.contract.methods.issueByPartition(
          partition1,
          tokenHolder,
          issuanceAmount,
          EMPTY_CERTIFICATE,
        ).encodeABI(),
        this.token,
        this.extension,
        this.clock, // this.clock
        controller
      );

      // await setCertificateActivated(
      //   this.extension,
      //   this.token,
      //   controller,
      //   CERTIFICATE_VALIDATION_NONE
      // )
      // await assertCertificateActivated(
      //   this.extension,
      //   this.token,
      //   CERTIFICATE_VALIDATION_NONE
      // );
      await this.token.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        certificate,
        { from: controller }
      );
      await assertIsTokenController(
        this.extension,
        this.token,
        tokenController1,
        false,
      );
      await addTokenController(
        this.extension,
        this.token,
        controller,
        tokenController1
      );
      await assertIsTokenController(
        this.extension,
        this.token,
        tokenController1,
        true,
      );
    });
 
    describe("when a partition has no expiry set", function () {
      it("returns false when getting the expiry activation status", async function () {
        const partitionExpiryActivated = await this.extension.getPartitionExpiryActivated(this.token.address, partition1);
        assert.equal(partitionExpiryActivated, false);
      });
      it("reverts when getting the expiry status", async function () {
        await expectRevert.unspecified(this.extension.getPartitionExpiryStatus(this.token.address, partition1));
      });
      it("reverts when getting the expiry timestamp", async function () {
        await expectRevert.unspecified(this.extension.getPartitionExpiryTimestamp(this.token.address, partition1));
      });
      describe("can still call transferByPartition", async function () {
        const transferAmount = 300;
        it.skip("transfers the requested amount", async function () {
          await setCertificateActivated(
            this.extension,
            this.token,
            controller,
            CERTIFICATE_VALIDATION_NONE
          )
          await assertCertificateActivated(
            this.extension,
            this.token,
            CERTIFICATE_VALIDATION_NONE
          );
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(this.token, recipient, partition1, 0);

          await this.token.transferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );

          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount - transferAmount
          );
          await assertBalanceOf(
            this.token,
            recipient,
            partition1,
            transferAmount
          );
        });
      });
      describe("only controllers can set an expiry timestamp", function () {
        it("allows controllers to set a valid expiry timestamp", async function () {
          const logs = await this.extension.setPartitionExpiryTimestamp(this.token.address, partition1, this.validTimestamp, { from: tokenController1 });
          const expiryActivated = await this.extension.getPartitionExpiryActivated(this.token.address, partition1);
          assert.equal(expiryActivated, true);
        });
        it("returns activated when a controller has set a valid expiry timestamp", async function () {
          const logs = await this.extension.setPartitionExpiryTimestamp(this.token.address, partition1, this.validTimestamp, { from: tokenController1 });
          const expiryActivated = await this.extension.getPartitionExpiryActivated(this.token.address, partition1);
          assert.equal(expiryActivated, true);
        });
        it("returns the expiry timestamp when a controller has set a valid expiry timestamp", async function () {
          const logs = await this.extension.setPartitionExpiryTimestamp(this.token.address, partition1, this.validTimestamp, { from: tokenController1 });
          const expiryTimestamp = await this.extension.getPartitionExpiryTimestamp(this.token.address, partition1);
          assert.equal(expiryTimestamp, this.validTimestamp);
        });
        it("reverts when controllers set an invalid expiry timestamp", async function () {
          await expectRevert.unspecified(this.extension.setPartitionExpiryTimestamp(this.token.address, partition1, this.invalidTimestamp, { from: tokenController1 }));
        });
        it("reverts when partition expiry is already activated", async function () {
          const logs = await this.extension.setPartitionExpiryTimestamp(this.token.address, partition1, this.validTimestamp, { from: tokenController1 });
          await expectRevert.unspecified(this.extension.setPartitionExpiryTimestamp(this.token.address, partition1, this.invalidTimestamp, { from: tokenController1 }));
        });
        it("reverts when non-controllers set a expiry timestamp", async function () {
          await expectRevert.unspecified(this.extension.setPartitionExpiryTimestamp(this.token.address, partition1, this.invalidTimestamp, {from: unknown }));
        });
      });
    });
 
    describe("when a partition has an expiry set", function () {
      beforeEach(async function () {
       await this.extension.setPartitionExpiryTimestamp(this.token.address, partition1, this.validTimestamp, { from: tokenController1 })
      });
 
     describe("when the partition has not expired", function () {
       it("returns true when getting the expiry activation status", async function () {
         const partitionExpiryActivated = await this.extension.getPartitionExpiryActivated(this.token.address, partition1);
         assert.equal(partitionExpiryActivated, true);
       });
       it("returns false when getting the expiry status", async function () {
         const partitionExpiryStatus = await this.extension.getPartitionExpiryStatus(this.token.address, partition1);
         assert.equal(partitionExpiryStatus, false);
       });
       it("returns the expiry time when getting the expirty timestamp", async function () {
         const partitionExpiryTimestamp = await this.extension.getPartitionExpiryTimestamp(this.token.address, partition1);
         assert.equal(partitionExpiryTimestamp, this.validTimestamp);
       });
       describe("can still call transferByPartition", async function () {
         const transferAmount = 300;
        //  const certificate = await craftCertificate(
        //   this.token.contract.methods.issueByPartition(
        //     partition1,
        //     tokenHolder,
        //     issuanceAmount,
        //     EMPTY_CERTIFICATE,
        //   ).encodeABI(),
        //   this.token,
        //   this.extension,
        //   this.clock, // this.clock
        //   controller
        // );
         it.skip("transfers the requested amount", async function () {
          await setCertificateActivated(
            this.extension,
            this.token,
            controller,
            CERTIFICATE_VALIDATION_NONE
          )
          await assertCertificateActivated(
            this.extension,
            this.token,
            CERTIFICATE_VALIDATION_NONE
          );
           await assertBalanceOf(
             this.token,
             tokenHolder,
             partition1,
             issuanceAmount
           );
           await assertBalanceOf(this.token, recipient, partition1, 0);
 
           await this.token.transferByPartition(
             partition1,
             recipient,
             transferAmount,
             EMPTY_CERTIFICATE,
             { from: tokenHolder }
           );
 
           await assertBalanceOf(
             this.token,
             tokenHolder,
             partition1,
             issuanceAmount - transferAmount
           );
           await assertBalanceOf(
             this.token,
             recipient,
             partition1,
             transferAmount
           );
         });
       });
     });
 
     describe("when the partition has expired", function () {
       beforeEach(async function () {
         await time.increaseTo(this.validTimestamp+1)
       });
       it("returns true when getting the expiry activation status", async function () {
         const partitionExpiryActivated = await this.extension.getPartitionExpiryActivated(this.token.address, partition1);
         assert.equal(partitionExpiryActivated, true);
       });
       it("returns true when getting the expiry status", async function () {
         const partitionExpiryStatus = await this.extension.getPartitionExpiryStatus(this.token.address, partition1);
         assert.equal(partitionExpiryStatus, true);
       });
       it("returns the expiry time when getting the expirty timestamp", async function () {
         const partitionExpiryTimestamp = await this.extension.getPartitionExpiryTimestamp(this.token.address, partition1);
         assert.equal(partitionExpiryTimestamp, this.validTimestamp);
       });
       describe("prevents transferByPartition", async function () {
         const transferAmount = 300;
        //  const certificate = await craftCertificate(
        //   this.token.contract.methods.issueByPartition(
        //     partition1,
        //     tokenHolder,
        //     issuanceAmount,
        //     EMPTY_CERTIFICATE,
        //   ).encodeABI(),
        //   this.token,
        //   this.extension,
        //   this.clock, // this.clock
        //   controller
        // );
         it("reverts when transfering the requested amount", async function () {
          await setCertificateActivated(
            this.extension,
            this.token,
            controller,
            CERTIFICATE_VALIDATION_NONE
          )
          await assertCertificateActivated(
            this.extension,
            this.token,
            CERTIFICATE_VALIDATION_NONE
          );
           await assertBalanceOf(
             this.token,
             tokenHolder,
             partition1,
             issuanceAmount
           );
           await assertBalanceOf(this.token, recipient, partition1, 0);
 
           await expectRevert.unspecified(this.token.transferByPartition(
             partition1,
             recipient,
             transferAmount,
             EMPTY_CERTIFICATE,
             { from: tokenHolder }
           ));
         });
       });
     });
   });
   });

  // PARTITION GRANULARITY ACTIVATED
  describe("setPartitionGranularityActivated", function () {
    beforeEach(async function () {
      await assertTokenHasExtension(
        this.registry,
        this.extension,
        this.token,
      );
    });
    describe("when the caller is the contract owner", function () {
      it("activates the partition granularity", async function () {
        await assertGranularityByPartitionActivated(
          this.extension,
          this.token,
          true
        );

        await setGranularityByPartitionActivated(
          this.extension,
          this.token,
          controller,
          false
        );

        await assertGranularityByPartitionActivated(
          this.extension,
          this.token,
          false
        )
      });
    });
    describe("when the caller is not the contract owner", function () {
      it("reverts", async function () {
        await expectRevert.unspecified(
          setGranularityByPartitionActivated(
            this.extension,
            this.token,
            unknown,
            false
          )
        );
      });
    });
  });
  
  // CANTRANSFER
  describe("canTransferByPartition/canOperatorTransferByPartition", function () {
    var localGranularity = 10;
    const transferAmount = 10 * localGranularity;

    before(async function () {
      this.senderContract = await ERC1400TokensSender.new({
        from: tokenHolder,
      });
      await this.registry.setInterfaceImplementer(
        tokenHolder,
        soliditySha3(ERC1400_TOKENS_SENDER),
        this.senderContract.address,
        { from: tokenHolder }
      );

      this.recipientContract = await ERC1400TokensRecipient.new({
        from: recipient,
      });
      await this.registry.setInterfaceImplementer(
        recipient,
        soliditySha3(ERC1400_TOKENS_RECIPIENT),
        this.recipientContract.address,
        { from: recipient }
      );
    });
    after(async function () {
      await this.registry.setInterfaceImplementer(
        tokenHolder,
        soliditySha3(ERC1400_TOKENS_SENDER),
        ZERO_ADDRESS,
        { from: tokenHolder }
      );
      await this.registry.setInterfaceImplementer(
        recipient,
        soliditySha3(ERC1400_TOKENS_RECIPIENT),
        ZERO_ADDRESS,
        { from: recipient }
      );
    });

    beforeEach(async function () {
      this.token2 = await ERC1400HoldableCertificate.new(
        "ERC1400Token",
        "DAU",
        localGranularity,
        [controller],
        partitions,
        this.extension.address,
        owner,
        CERTIFICATE_SIGNER,
        CERTIFICATE_VALIDATION_DEFAULT,
        { from: controller }
      );

      const certificate = await craftCertificate(
        this.token2.contract.methods.issueByPartition(
          partition1,
          tokenHolder,
          issuanceAmount,
          EMPTY_CERTIFICATE,
        ).encodeABI(),
        this.token2,
        this.extension,
        this.clock, // this.clock
        controller
      )
      await this.token2.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        certificate,
        { from: controller }
      );
    });

    describe("when checker has been setup", function () {
      before(async function () {
        this.checkerContract = await ERC1400TokensChecker.new({
          from: owner,
        });
      });
      beforeEach(async function () {
        await this.token2.setTokenExtension(
          this.checkerContract.address,
          ERC1400_TOKENS_CHECKER,
          true,
          true,
          true,
          { from: owner }
        );
      });
      describe("when certificate is valid", function () {
        describe("when the operator is authorized", function () {
          describe("when balance is sufficient", function () {
            describe("when receiver is not the zero address", function () {
              describe("when sender is eligible", function () {
                describe("when validator is ok", function () {
                  describe("when receiver is eligible", function () {
                    describe("when the amount is a multiple of the granularity", function () {
                      it("returns Ethereum status code 51 (canTransferByPartition)", async function () {
                        const certificate = await craftCertificate(
                          this.token2.contract.methods.transferByPartition(
                            partition1,
                            recipient,
                            transferAmount,
                            EMPTY_CERTIFICATE,
                          ).encodeABI(),
                          this.token2,
                          this.extension,
                          this.clock, // this.clock
                          tokenHolder
                        )
                        const response = await this.token2.canTransferByPartition(
                          partition1,
                          recipient,
                          transferAmount,
                          certificate,
                          { from: tokenHolder }
                        );
                        await assertEscResponse(
                          response,
                          ESC_51,
                          EMPTY_BYTE32,
                          partition1
                        );
                      });
                      it("returns Ethereum status code 51 (canOperatorTransferByPartition)", async function () {
                        const certificate = await craftCertificate(
                          this.token2.contract.methods.operatorTransferByPartition(
                            partition1,
                            tokenHolder,
                            recipient,
                            transferAmount,
                            ZERO_BYTE,
                            EMPTY_CERTIFICATE,
                          ).encodeABI(),
                          this.token2,
                          this.extension,
                          this.clock, // this.clock
                          tokenHolder
                        )
                        const response = await this.token2.canOperatorTransferByPartition(
                          partition1,
                          tokenHolder,
                          recipient,
                          transferAmount,
                          ZERO_BYTE,
                          certificate,
                          { from: tokenHolder }
                        );
                        await assertEscResponse(
                          response,
                          ESC_51,
                          EMPTY_BYTE32,
                          partition1
                        );
                      });
                    });
                    describe("when the amount is not a multiple of the granularity", function () {
                      it("returns Ethereum status code 50", async function () {
                        const certificate = await craftCertificate(
                          this.token2.contract.methods.transferByPartition(
                            partition1,
                            recipient,
                            1, // transferAmount
                            EMPTY_CERTIFICATE,
                          ).encodeABI(),
                          this.token2,
                          this.extension,
                          this.clock, // this.clock
                          tokenHolder
                        )
                        const response = await this.token2.canTransferByPartition(
                          partition1,
                          recipient,
                          1, // transferAmount
                          certificate,
                          { from: tokenHolder }
                        );
                        await assertEscResponse(
                          response,
                          ESC_50,
                          EMPTY_BYTE32,
                          partition1
                        );
                      });
                    });
                  });
                  describe("when receiver is not eligible", function () {
                    it("returns Ethereum status code 57", async function () {
                      await setCertificateActivated(
                        this.extension,
                        this.token2,
                        controller,
                        CERTIFICATE_VALIDATION_NONE
                      );
              
                      await assertCertificateActivated(
                        this.extension,
                        this.token2,
                        CERTIFICATE_VALIDATION_NONE
                      )
  
                      await this.extension.addAllowlisted(this.token2.address, tokenHolder, {
                        from: controller,
                      });
                      await this.extension.addAllowlisted(this.token2.address, recipient, {
                        from: controller,
                      });
  
                      const response = await this.token2.canTransferByPartition(
                        partition1,
                        recipient,
                        transferAmount,
                        INVALID_CERTIFICATE_RECIPIENT,
                        { from: tokenHolder }
                      );
                      await assertEscResponse(
                        response,
                        ESC_57,
                        EMPTY_BYTE32,
                        partition1
                      );
                    });
                  });
                });
              });
              describe("when sender is not eligible", function () {
                it("returns Ethereum status code 56", async function () {
                  const response = await this.token2.canTransferByPartition(
                    partition1,
                    recipient,
                    transferAmount,
                    INVALID_CERTIFICATE_SENDER,
                    { from: tokenHolder }
                  );
                  await assertEscResponse(
                    response,
                    ESC_56,
                    EMPTY_BYTE32,
                    partition1
                  );
                });
              });
            });
            describe("when receiver is the zero address", function () {
              it("returns Ethereum status code 57", async function () {
                const certificate = await craftCertificate(
                  this.token2.contract.methods.transferByPartition(
                    partition1,
                    ZERO_ADDRESS,
                    transferAmount,
                    EMPTY_CERTIFICATE,
                  ).encodeABI(),
                  this.token2,
                  this.extension,
                  this.clock, // this.clock
                  tokenHolder
                )
                const response = await this.token2.canTransferByPartition(
                  partition1,
                  ZERO_ADDRESS,
                  transferAmount,
                  certificate,
                  { from: tokenHolder }
                );
                await assertEscResponse(
                  response,
                  ESC_57,
                  EMPTY_BYTE32,
                  partition1
                );
              });
            });
          });
          describe("when balance is not sufficient", function () {
            it("returns Ethereum status code 52 (insuficient global balance)", async function () {
              const certificate = await craftCertificate(
                this.token2.contract.methods.transferByPartition(
                  partition1,
                  recipient,
                  issuanceAmount + localGranularity,
                  EMPTY_CERTIFICATE,
                ).encodeABI(),
                this.token2,
                this.extension,
                this.clock, // this.clock
                tokenHolder
              )
              const response = await this.token2.canTransferByPartition(
                partition1,
                recipient,
                issuanceAmount + localGranularity,
                certificate,
                { from: tokenHolder }
              );
              await assertEscResponse(
                response,
                ESC_52,
                EMPTY_BYTE32,
                partition1
              );
            });
            it("returns Ethereum status code 52 (insuficient partition balance)", async function () {
              const issuanceCertificate = await craftCertificate(
                this.token2.contract.methods.issueByPartition(
                  partition2,
                  tokenHolder,
                  localGranularity,
                  EMPTY_CERTIFICATE,
                ).encodeABI(),
                this.token2,
                this.extension,
                this.clock, // this.clock
                controller
              )
              await this.token2.issueByPartition(
                partition2,
                tokenHolder,
                localGranularity,
                issuanceCertificate,
                { from: controller }
              );
              const certificate = await craftCertificate(
                this.token2.contract.methods.transferByPartition(
                  partition2,
                  recipient,
                  transferAmount,
                  EMPTY_CERTIFICATE,
                ).encodeABI(),
                this.token2,
                this.extension,
                this.clock, // this.clock
                tokenHolder
              )
              const response = await this.token2.canTransferByPartition(
                partition2,
                recipient,
                transferAmount,
                certificate,
                { from: tokenHolder }
              );
              await assertEscResponse(
                response,
                ESC_52,
                EMPTY_BYTE32,
                partition2
              );
            });
          });
        });
        describe("when the operator is not authorized", function () {
          it("returns Ethereum status code 58 (canOperatorTransferByPartition)", async function () {
            const certificate = await craftCertificate(
              this.token2.contract.methods.operatorTransferByPartition(
                partition1,
                operator,
                recipient,
                transferAmount,
                ZERO_BYTE,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token2,
              this.extension,
              this.clock, // this.clock
              tokenHolder
            )
            const response = await this.token2.canOperatorTransferByPartition(
              partition1,
              operator,
              recipient,
              transferAmount,
              ZERO_BYTE,
              certificate,
              { from: tokenHolder }
            );
            await assertEscResponse(response, ESC_58, EMPTY_BYTE32, partition1);
          });
        });
      });
      describe("when certificate is not valid", function () {
        it("returns Ethereum status code 54 (canTransferByPartition)", async function () {
          const response = await this.token2.canTransferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );
          await assertEscResponse(response, ESC_54, EMPTY_BYTE32, partition1);
        });
        it("returns Ethereum status code 54 (canOperatorTransferByPartition)", async function () {
          const response = await this.token2.canOperatorTransferByPartition(
            partition1,
            tokenHolder,
            recipient,
            transferAmount,
            ZERO_BYTE,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );
          await assertEscResponse(response, ESC_54, EMPTY_BYTE32, partition1);
        });
      });
    });
    describe("when checker has not been setup", function () {
      it("returns empty Ethereum status code 00 (canTransferByPartition)", async function () {
        const certificate = await craftCertificate(
          this.token2.contract.methods.transferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
          ).encodeABI(),
          this.token2,
          this.extension,
          this.clock, // this.clock
          tokenHolder
        )
        const response = await this.token2.canTransferByPartition(
          partition1,
          recipient,
          transferAmount,
          certificate,
          { from: tokenHolder }
        );
        await assertEscResponse(response, ESC_00, EMPTY_BYTE32, partition1);
      });
    });
  });

  // CERTIFICATE EXTENSION
  describe("certificate", function () {
    const redeemAmount = 50;
    const transferAmount = 300;
    beforeEach(async function () {
      await assertTokenHasExtension(
        this.registry,
        this.extension,
        this.token,
      );

      await assertCertificateActivated(
        this.extension,
        this.token,
        CERTIFICATE_VALIDATION_SALT
      )

      await assertAllowListActivated(
        this.extension,
        this.token,
        true
      )

      const certificate = await craftCertificate(
        this.token.contract.methods.issueByPartition(
          partition1,
          tokenHolder,
          issuanceAmount,
          EMPTY_CERTIFICATE,
        ).encodeABI(),
        this.token,
        this.extension,
        this.clock, // this.clock
        controller
      )

      await this.token.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        certificate,
        { from: controller }
      );
    });
    describe("when certificate is valid", function () {
      describe("ERC1400 functions", function () {
        describe("issue", function () {
          it("issues new tokens when certificate is provided", async function () {
            const certificate = await craftCertificate(
              this.token.contract.methods.issue(
                tokenHolder,
                issuanceAmount,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              controller
            )
            await this.token.issue(
              tokenHolder,
              issuanceAmount,
              certificate,
              { from: controller }
            );
            await assertTotalSupply(this.token, 2 * issuanceAmount);
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              2 * issuanceAmount
            );
          });
          it("fails issuing when when certificate is not provided", async function () {
            await expectRevert.unspecified(this.token.issue(
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
              { from: controller }
            ));
          });
        });
        describe("issueByPartition", function () {
          it("issues new tokens when certificate is provided", async function () {
            const certificate = await craftCertificate(
              this.token.contract.methods.issueByPartition(
                partition1,
                tokenHolder,
                issuanceAmount,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              controller
            )
            await this.token.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              certificate,
              { from: controller }
            );
            await assertTotalSupply(this.token, 2 * issuanceAmount);
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              2 * issuanceAmount
            );
          });
          it("issues new tokens when certificate is not provided, but sender is certificate signer", async function () {
            await this.extension.addCertificateSigner(this.token.address, controller, { from: controller});
            await this.token.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
              { from: controller }
            );
            await assertTotalSupply(this.token, 2 * issuanceAmount);
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              2 * issuanceAmount
            );
          });
          it("fails issuing when certificate is not provided", async function () {
            await expectRevert.unspecified(this.token.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
              { from: controller }
            ));
          });
          it("fails issuing when certificate is not provided (even if allowlisted)", async function () {
            await this.extension.addAllowlisted(this.token.address, tokenHolder, {
              from: controller,
            });
            await expectRevert.unspecified(this.token.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
              { from: controller }
            ));
          });
        });
        describe("redeem", function () {
          it("redeeems the requested amount when certificate is provided", async function () {
            await assertTotalSupply(this.token, issuanceAmount);
            await assertBalance(this.token, tokenHolder, issuanceAmount);
  
            const certificate = await craftCertificate(
              this.token.contract.methods.redeem(
                issuanceAmount,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              tokenHolder
            )
            await this.token.redeem(issuanceAmount, certificate, {
              from: tokenHolder,
            });
  
            await assertTotalSupply(this.token, 0);
            await assertBalance(this.token, tokenHolder, 0);
          });
          it("fails redeeming when certificate is not provided", async function () {
            await assertTotalSupply(this.token, issuanceAmount);
            await assertBalance(this.token, tokenHolder, issuanceAmount);
  
            await expectRevert.unspecified(this.token.redeem(issuanceAmount, EMPTY_CERTIFICATE, {
              from: tokenHolder,
            }));
  
            await assertTotalSupply(this.token, issuanceAmount);
            await assertBalance(this.token, tokenHolder, issuanceAmount);
          });
        });
        describe("redeemFrom", function () {
          it("redeems the requested amount when certificate is provided", async function () {
            await assertTotalSupply(this.token, issuanceAmount);
            await assertBalance(this.token, tokenHolder, issuanceAmount);
  
            await this.token.authorizeOperator(operator, { from: tokenHolder });
  
            const certificate = await craftCertificate(
              this.token.contract.methods.redeemFrom(
                tokenHolder,
                issuanceAmount,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              operator
            )
            await this.token.redeemFrom(
              tokenHolder,
              issuanceAmount,
              certificate,
              { from: operator }
            );
  
            await assertTotalSupply(this.token, 0);
            await assertBalance(this.token, tokenHolder, 0);
          });
          it("fails redeeming the requested amount when certificate is not provided", async function () {
            await assertTotalSupply(this.token, issuanceAmount);
            await assertBalance(this.token, tokenHolder, issuanceAmount);
  
            await this.token.authorizeOperator(operator, { from: tokenHolder });
            await expectRevert.unspecified(this.token.redeemFrom(
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
              { from: operator }
            ));
  
            await assertTotalSupply(this.token, issuanceAmount);
            await assertBalance(this.token, tokenHolder, issuanceAmount);
          });
        });
        describe("redeemByPartition", function () {
          it("redeems the requested amount when certificate is provided", async function () {
            const certificate = await craftCertificate(
              this.token.contract.methods.redeemByPartition(
                partition1,
                redeemAmount,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              tokenHolder
            )
            await this.token.redeemByPartition(
              partition1,
              redeemAmount,
              certificate,
              { from: tokenHolder }
            );
            await assertTotalSupply(this.token, issuanceAmount - redeemAmount);
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount - redeemAmount
            );
          });
          it("fails redeems when sender when certificate is not provided", async function () {
            await expectRevert.unspecified(this.token.redeemByPartition(
              partition1,
              redeemAmount,
              EMPTY_CERTIFICATE,
              { from: tokenHolder }
            ));
            await assertTotalSupply(this.token, issuanceAmount);
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
          });
          it("fails redeems when sender when certificate is not provided (even if allowlisted)", async function () {
            await this.extension.addAllowlisted(this.token.address, tokenHolder, {
              from: controller,
            });
            await expectRevert.unspecified(this.token.redeemByPartition(
              partition1,
              redeemAmount,
              EMPTY_CERTIFICATE,
              { from: tokenHolder }
            ));
            await assertTotalSupply(this.token, issuanceAmount);
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
          });
        });
        describe("operatorRedeemByPartition", function () {
          it("redeems the requested amount when certificate is provided", async function () {
            await this.token.authorizeOperatorByPartition(partition1, operator, {
              from: tokenHolder,
            });
  
            const certificate = await craftCertificate(
              this.token.contract.methods.operatorRedeemByPartition(
                partition1,
                tokenHolder,
                redeemAmount,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              operator
            )
            await this.token.operatorRedeemByPartition(
              partition1,
              tokenHolder,
              redeemAmount,
              certificate,
              { from: operator }
            );
  
            await assertTotalSupply(this.token, issuanceAmount - redeemAmount);
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount - redeemAmount
            );
          });
          it("redeems the requested amount when certificate is provided, but sender is certificate signer", async function () {
            await this.token.authorizeOperatorByPartition(partition1, operator, {
              from: tokenHolder,
            });
  
            await this.extension.addCertificateSigner(this.token.address, operator, { from: controller});

            await this.token.operatorRedeemByPartition(
              partition1,
              tokenHolder,
              redeemAmount,
              EMPTY_CERTIFICATE,
              { from: operator }
            );
  
            await assertTotalSupply(this.token, issuanceAmount - redeemAmount);
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount - redeemAmount
            );
          });
          it("fails redeeming when certificate is not provided", async function () {
            await this.token.authorizeOperatorByPartition(partition1, operator, {
              from: tokenHolder,
            });
            await expectRevert.unspecified(this.token.operatorRedeemByPartition(
              partition1,
              tokenHolder,
              redeemAmount,
              EMPTY_CERTIFICATE,
              { from: operator }
            ));
  
            await assertTotalSupply(this.token, issuanceAmount);
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
          });
        });
        describe("transferWithData", function () {
          it("transfers the requested amount when certificate is provided", async function () {
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            const certificate = await craftCertificate(
              this.token.contract.methods.transferWithData(
                recipient,
                transferAmount,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              tokenHolder
            )
            await this.token.transferWithData(
              recipient,
              transferAmount,
              certificate,
              { from: tokenHolder }
            );
  
            await assertBalance(
              this.token,
              tokenHolder,
              issuanceAmount - transferAmount
            );
            await assertBalance(this.token, recipient, transferAmount);
          });
          it("fails transferring when certificate is not provided", async function () {
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            await expectRevert.unspecified(this.token.transferWithData(
              recipient,
              transferAmount,
              EMPTY_CERTIFICATE,
              { from: tokenHolder }
            ));
  
            await assertBalance(
              this.token,
              tokenHolder,
              issuanceAmount
            );
            await assertBalance(this.token, recipient, 0);
          });
        });
        describe("transferFromWithData", function () {
          it("transfers the requested amount when certificate is provided", async function () {
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            await this.token.authorizeOperator(operator, { from: tokenHolder });
  
            const certificate = await craftCertificate(
              this.token.contract.methods.transferFromWithData(
                tokenHolder,
                recipient,
                transferAmount,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              operator
            )
            await this.token.transferFromWithData(
              tokenHolder,
              recipient,
              transferAmount,
              certificate,
              { from: operator }
            );
  
            await assertBalance(
              this.token,
              tokenHolder,
              issuanceAmount - transferAmount
            );
            await assertBalance(this.token, recipient, transferAmount);
          });
          it("fails transferring when certificate is not provided", async function () {
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            await this.token.authorizeOperator(operator, { from: tokenHolder });
  
            await expectRevert.unspecified(this.token.transferFromWithData(
              tokenHolder,
              recipient,
              transferAmount,
              EMPTY_CERTIFICATE,
              { from: operator }
            ));
  
            await assertBalance(
              this.token,
              tokenHolder,
              issuanceAmount
            );
            await assertBalance(this.token, recipient, 0);
          });
        });
        describe("transferByPartition", function () {
          it("transfers the requested amount when certificate is provided", async function () {
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
            await assertBalanceOf(this.token, recipient, partition1, 0);
  
            const certificate = await craftCertificate(
              this.token.contract.methods.transferByPartition(
                partition1,
                recipient,
                transferAmount,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              tokenHolder
            )
            await this.token.transferByPartition(
              partition1,
              recipient,
              transferAmount,
              certificate,
              { from: tokenHolder }
            );
  
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount - transferAmount
            );
            await assertBalanceOf(
              this.token,
              recipient,
              partition1,
              transferAmount
            );
          });
          it("fails transferring when certificate is not provided", async function () {
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
            await assertBalanceOf(this.token, recipient, partition1, 0);
  
            await expectRevert.unspecified(this.token.transferByPartition(
              partition1,
              recipient,
              transferAmount,
              EMPTY_CERTIFICATE,
              { from: tokenHolder }
            ));
  
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
            await assertBalanceOf(
              this.token,
              recipient,
              partition1,
              0
            );
          });
          it("fails transferring when certificate is not provided (even when allowlisted)", async function () {
            await this.extension.addAllowlisted(this.token.address, tokenHolder, {
              from: controller,
            });
            await this.extension.addAllowlisted(this.token.address, recipient, {
              from: controller,
            });
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
            await assertBalanceOf(this.token, recipient, partition1, 0);
  
            await expectRevert.unspecified(this.token.transferByPartition(
              partition1,
              recipient,
              transferAmount,
              EMPTY_CERTIFICATE,
              { from: tokenHolder }
            ));
  
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
            await assertBalanceOf(
              this.token,
              recipient,
              partition1,
              0
            );
          });
        });
        describe("operatorTransferByPartition", function () {
          it("transfers the requested amount when certificate is provided", async function () {
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
            await assertBalanceOf(this.token, recipient, partition1, 0);
            assert.equal(
              await this.token.allowanceByPartition(
                partition1,
                tokenHolder,
                operator
              ),
              0
            );
  
            const approvedAmount = 400;
            await this.token.approveByPartition(
              partition1,
              operator,
              approvedAmount,
              { from: tokenHolder }
            );
            assert.equal(
              await this.token.allowanceByPartition(
                partition1,
                tokenHolder,
                operator
              ),
              approvedAmount
            );
            const certificate = await craftCertificate(
              this.token.contract.methods.operatorTransferByPartition(
                partition1,
                tokenHolder,
                recipient,
                transferAmount,
                ZERO_BYTE,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              operator
            )
            await this.token.operatorTransferByPartition(
              partition1,
              tokenHolder,
              recipient,
              transferAmount,
              ZERO_BYTE,
              certificate,
              { from: operator }
            );
  
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount - transferAmount
            );
            await assertBalanceOf(
              this.token,
              recipient,
              partition1,
              transferAmount
            );
            assert.equal(
              await this.token.allowanceByPartition(
                partition1,
                tokenHolder,
                operator
              ),
              approvedAmount - transferAmount
            );
          });
          it("transfers the requested amount when certificate is provided, but sender is certificate signer", async function () {
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
            await assertBalanceOf(this.token, recipient, partition1, 0);
            assert.equal(
              await this.token.allowanceByPartition(
                partition1,
                tokenHolder,
                operator
              ),
              0
            );
  
            const approvedAmount = 400;
            await this.token.approveByPartition(
              partition1,
              operator,
              approvedAmount,
              { from: tokenHolder }
            );
            assert.equal(
              await this.token.allowanceByPartition(
                partition1,
                tokenHolder,
                operator
              ),
              approvedAmount
            );

            await this.extension.addCertificateSigner(this.token.address, operator, { from: controller});
            await this.token.operatorTransferByPartition(
              partition1,
              tokenHolder,
              recipient,
              transferAmount,
              ZERO_BYTE,
              EMPTY_CERTIFICATE,
              { from: operator }
            );
  
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount - transferAmount
            );
            await assertBalanceOf(
              this.token,
              recipient,
              partition1,
              transferAmount
            );
            assert.equal(
              await this.token.allowanceByPartition(
                partition1,
                tokenHolder,
                operator
              ),
              approvedAmount - transferAmount
            );
          });
          it("updates the token partition", async function () {
            await assertBalanceOfByPartition(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
  
            const updateAmount = 400;

            const certificate = await craftCertificate(
              this.token.contract.methods.operatorTransferByPartition(
                partition1,
                tokenHolder,
                tokenHolder,
                updateAmount,
                changeToPartition2,
                EMPTY_CERTIFICATE,
              ).encodeABI(),
              this.token,
              this.extension,
              this.clock, // this.clock
              controller
            )
            await this.token.operatorTransferByPartition(
              partition1,
              tokenHolder,
              tokenHolder,
              updateAmount,
              changeToPartition2,
              certificate,
              { from: controller }
            );
  
            await assertBalanceOfByPartition(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount - updateAmount
            );
            await assertBalanceOfByPartition(
              this.token,
              tokenHolder,
              partition2,
              updateAmount
            );
          });
          it("fails transferring when certificate is not provided", async function () {
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
            await assertBalanceOf(this.token, recipient, partition1, 0);
            assert.equal(
              await this.token.allowanceByPartition(
                partition1,
                tokenHolder,
                operator
              ),
              0
            );
  
            const approvedAmount = 400;
            await this.token.approveByPartition(
              partition1,
              operator,
              approvedAmount,
              { from: tokenHolder }
            );
            assert.equal(
              await this.token.allowanceByPartition(
                partition1,
                tokenHolder,
                operator
              ),
              approvedAmount
            );
            await expectRevert.unspecified(this.token.operatorTransferByPartition(
              partition1,
              tokenHolder,
              recipient,
              transferAmount,
              ZERO_BYTE,
              EMPTY_CERTIFICATE,
              { from: operator }
            ));
  
            await assertBalanceOf(
              this.token,
              tokenHolder,
              partition1,
              issuanceAmount
            );
            await assertBalanceOf(
              this.token,
              recipient,
              partition1,
              0
            );
            assert.equal(
              await this.token.allowanceByPartition(
                partition1,
                tokenHolder,
                operator
              ),
              approvedAmount
            );
          });
        });
      });
      describe("ERC20 functions", function () {
        describe("transfer", function () {
          it("transfers the requested amount when sender and recipient are allowlisted", async function () {
            await this.extension.addAllowlisted(this.token.address, tokenHolder, {
              from: controller,
            });
            await this.extension.addAllowlisted(this.token.address, recipient, {
              from: controller,
            });
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            await this.token.transfer(recipient, transferAmount, {
              from: tokenHolder,
            });
  
            await assertBalance(this.token, tokenHolder, issuanceAmount - transferAmount);
            await assertBalance(this.token, recipient, transferAmount);
          });
          it("fails transferring when sender and is not allowlisted", async function () {
            await this.extension.addAllowlisted(this.token.address, recipient, {
              from: controller,
            });
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            await expectRevert.unspecified(
              this.token.transfer(recipient, transferAmount, {
                from: tokenHolder,
              })
            );
  
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
          });
          it("fails transferring when recipient and is not allowlisted", async function () {
            await this.extension.addAllowlisted(this.token.address, tokenHolder, {
              from: controller,
            });
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            await expectRevert.unspecified(
              this.token.transfer(recipient, transferAmount, {
                from: tokenHolder,
              })
            );
  
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
          });
        });
        describe("transferFrom", function () {
          it("transfers the requested amount when sender and recipient are allowlisted", async function () {
            await this.extension.addAllowlisted(this.token.address, tokenHolder, {
              from: controller,
            });
            await this.extension.addAllowlisted(this.token.address, recipient, {
              from: controller,
            });
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            await this.token.authorizeOperator(operator, { from: tokenHolder });
            await  this.token.transferFrom(tokenHolder, recipient, transferAmount, {
              from: operator,
            });
  
            await assertBalance(this.token, tokenHolder, issuanceAmount - transferAmount);
            await assertBalance(this.token, recipient, transferAmount);
          });
          it("fails transferring when sender is not allowlisted", async function () {
            await this.extension.addAllowlisted(this.token.address, recipient, {
              from: controller,
            });
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            await this.token.authorizeOperator(operator, { from: tokenHolder });
            await expectRevert.unspecified(
              this.token.transferFrom(tokenHolder, recipient, transferAmount, {
                from: operator,
              })
            );
  
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
          });
          it("fails transferring when recipient is not allowlisted", async function () {
            await this.extension.addAllowlisted(this.token.address, tokenHolder, {
              from: controller,
            });
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
  
            await this.token.authorizeOperator(operator, { from: tokenHolder });
            await expectRevert.unspecified(
              this.token.transferFrom(tokenHolder, recipient, transferAmount, {
                from: operator,
              })
            );
  
            await assertBalance(this.token, tokenHolder, issuanceAmount);
            await assertBalance(this.token, recipient, 0);
          });
          
        });
      });
    });
    describe("when certificate is not valid", function () {
      describe("salt-based certificate control", function () {
        it("issues new tokens when certificate is valid", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          );
          await assertTotalSupply(this.token, 2 * issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            2 * issuanceAmount
          );
        });
        it("fails issuing when certificate is not valid (wrong function selector)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.operatorRedeemByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (wrong parameter)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount-1,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (expiration time is past)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )

          // Wait until certificate expiration
          await advanceTimeAndBlock(CERTIFICATE_VALIDITY_PERIOD * SECONDS_IN_AN_HOUR + 100);

          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate already used)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          );
          await assertTotalSupply(this.token, 2 * issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            2 * issuanceAmount
          );
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
          
        });
        it("fails issuing when certificate is not valid (certificate signer has been revoked)", async function () {
          await this.extension.removeCertificateSigner(this.token.address, CERTIFICATE_SIGNER, { from: controller });

          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (wrong transaction sender)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            tokenHolder
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate too long) [for coverage]", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate.concat('0'),
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate with v=27) [for coverage]", async function () {
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            SALT_CERTIFICATE_WITH_V_EQUAL_TO_27,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate with v=28) [for coverage]", async function () {
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            SALT_CERTIFICATE_WITH_V_EQUAL_TO_28,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate with v=29) [for coverage]", async function () {
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            SALT_CERTIFICATE_WITH_V_EQUAL_TO_29,
            { from: controller }
          ));
        });
      });
      describe("nonce-based certificate control", function () {
        beforeEach(async function () {
          await setCertificateActivated(
            this.extension,
            this.token,
            controller,
            CERTIFICATE_VALIDATION_NONCE
          );
  
          await assertCertificateActivated(
            this.extension,
            this.token,
            CERTIFICATE_VALIDATION_NONCE
          )
        });
        it("issues new tokens when certificate is valid", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          );
          await assertTotalSupply(this.token, 2 * issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            2 * issuanceAmount
          );
        });
        it("fails issuing when certificate is not valid (wrong function selector)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.operatorRedeemByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (wrong parameter)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount-1,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (expiration time is past)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )

          // Wait until certificate expiration
          await advanceTimeAndBlock(CERTIFICATE_VALIDITY_PERIOD * SECONDS_IN_AN_HOUR + 100);

          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate already used)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          );
          await assertTotalSupply(this.token, 2 * issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            2 * issuanceAmount
          );
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
          
        });
        it("fails issuing when certificate is not valid (certificate signer has been revoked)", async function () {
          await this.extension.removeCertificateSigner(this.token.address, CERTIFICATE_SIGNER, { from: controller });

          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (wrong transaction sender)", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            tokenHolder
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate too long) [for coverage]", async function () {
          const certificate = await craftCertificate(
            this.token.contract.methods.issueByPartition(
              partition1,
              tokenHolder,
              issuanceAmount,
              EMPTY_CERTIFICATE,
            ).encodeABI(),
            this.token,
            this.extension,
            this.clock, // this.clock
            controller
          )
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            certificate.concat('0'),
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate with v=27) [for coverage]", async function () {
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            NONCE_CERTIFICATE_WITH_V_EQUAL_TO_27,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate with v=28) [for coverage]", async function () {
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            NONCE_CERTIFICATE_WITH_V_EQUAL_TO_28,
            { from: controller }
          ));
        });
        it("fails issuing when certificate is not valid (certificate with v=29) [for coverage]", async function () {
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            NONCE_CERTIFICATE_WITH_V_EQUAL_TO_29,
            { from: controller }
          ));
        });
      });
    });
  });

  // ALLOWLIST EXTENSION
  describe("allowlist", function () {
    const redeemAmount = 50;
    const transferAmount = 300;
    beforeEach(async function () {
      await assertTokenHasExtension(
        this.registry,
        this.extension,
        this.token,
      );

      await setCertificateActivated(
        this.extension,
        this.token,
        controller,
        CERTIFICATE_VALIDATION_NONE
      );

      await assertCertificateActivated(
        this.extension,
        this.token,
        CERTIFICATE_VALIDATION_NONE
      )

      await assertAllowListActivated(
        this.extension,
        this.token,
        true
      )

      await this.extension.addAllowlisted(this.token.address, tokenHolder, {
        from: controller,
      });

      await this.token.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        EMPTY_CERTIFICATE,
        { from: controller }
      );
    });
    describe("ERC1400 functions", function () {
      describe("issue", function () {
        it("issues new tokens when recipient is allowlisted", async function () {
          await this.token.issue(
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: controller }
          );
          await assertTotalSupply(this.token, 2 * issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            2 * issuanceAmount
          );
        });
        it("fails issuing when recipient is not allowlisted", async function () {
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await expectRevert.unspecified(this.token.issue(
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: controller }
          ));
        });
      });
      describe("issueByPartition", function () {
        it("issues new tokens when recipient is allowlisted", async function () {
          await this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: controller }
          );
          await assertTotalSupply(this.token, 2 * issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            2 * issuanceAmount
          );
        });
        it("fails issuing when recipient is not allowlisted", async function () {
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: controller }
          ));
        });
      });
      describe("redeem", function () {
        it("redeeems the requested amount when sender is allowlisted", async function () {
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);

          await this.token.redeem(issuanceAmount, EMPTY_CERTIFICATE, {
            from: tokenHolder,
          });

          await assertTotalSupply(this.token, 0);
          await assertBalance(this.token, tokenHolder, 0);
        });
        it("fails redeeming when sender is not allowlisted", async function () {
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);

          await expectRevert.unspecified(this.token.redeem(issuanceAmount, EMPTY_CERTIFICATE, {
            from: tokenHolder,
          }));

          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);
        });
      });
      describe("redeemFrom", function () {
        it("redeems the requested amount when sender is allowlisted", async function () {
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await this.token.redeemFrom(
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          );

          await assertTotalSupply(this.token, 0);
          await assertBalance(this.token, tokenHolder, 0);
        });
        it("fails redeeming the requested amount when sender is not allowlisted", async function () {
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await expectRevert.unspecified(this.token.redeemFrom(
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          ));

          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);
        });
      });
      describe("redeemByPartition", function () {
        it("redeems the requested amount when sender is allowlisted", async function () {
          await this.token.redeemByPartition(
            partition1,
            redeemAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );
          await assertTotalSupply(this.token, issuanceAmount - redeemAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount - redeemAmount
          );
        });
        it("fails redeems when sender is not allowlisted", async function () {
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await expectRevert.unspecified(this.token.redeemByPartition(
            partition1,
            redeemAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
        });
      });
      describe("operatorRedeemByPartition", function () {
        it("redeems the requested amount when sender is allowlisted", async function () {
          await this.token.authorizeOperatorByPartition(partition1, operator, {
            from: tokenHolder,
          });
          await this.token.operatorRedeemByPartition(
            partition1,
            tokenHolder,
            redeemAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          );

          await assertTotalSupply(this.token, issuanceAmount - redeemAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount - redeemAmount
          );
        });
        it("fails redeeming when sender is not allowlisted", async function () {
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await this.token.authorizeOperatorByPartition(partition1, operator, {
            from: tokenHolder,
          });
          await expectRevert.unspecified(this.token.operatorRedeemByPartition(
            partition1,
            tokenHolder,
            redeemAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          ));

          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
        });
      });
      describe("transferWithData", function () {
        it("transfers the requested amount when sender and recipient are allowlisted", async function () {
          await this.extension.addAllowlisted(this.token.address, recipient, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.transferWithData(
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );

          await assertBalance(
            this.token,
            tokenHolder,
            issuanceAmount - transferAmount
          );
          await assertBalance(this.token, recipient, transferAmount);
        });
        it("fails transferring when sender is not allowlisted", async function () {
          await this.extension.addAllowlisted(this.token.address, recipient, {
            from: controller,
          });
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await expectRevert.unspecified(this.token.transferWithData(
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));

          await assertBalance(
            this.token,
            tokenHolder,
            issuanceAmount
          );
          await assertBalance(this.token, recipient, 0);
        });
        it("fails transferring when recipient is not allowlisted", async function () {
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await expectRevert.unspecified(this.token.transferWithData(
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));

          await assertBalance(
            this.token,
            tokenHolder,
            issuanceAmount
          );
          await assertBalance(this.token, recipient, 0);
        });
      });
      describe("transferFromWithData", function () {
        it("transfers the requested amount when sender and recipient are allowliste", async function () {
          await this.extension.addAllowlisted(this.token.address, recipient, {
            from: controller,
          });

          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await this.token.transferFromWithData(
            tokenHolder,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          );

          await assertBalance(
            this.token,
            tokenHolder,
            issuanceAmount - transferAmount
          );
          await assertBalance(this.token, recipient, transferAmount);
        });
      });
      describe("transferByPartition", function () {
        it("transfers the requested amount when sender and recipient are allowlisted", async function () {
          await this.extension.addAllowlisted(this.token.address, recipient, {
            from: controller,
          });
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(this.token, recipient, partition1, 0);

          await this.token.transferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );

          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount - transferAmount
          );
          await assertBalanceOf(
            this.token,
            recipient,
            partition1,
            transferAmount
          );
        });
        it("fails transferring when sender is not allowlisted", async function () {
          await this.extension.addAllowlisted(this.token.address, recipient, {
            from: controller,
          });
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(this.token, recipient, partition1, 0);

          await expectRevert.unspecified(this.token.transferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));

          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(
            this.token,
            recipient,
            partition1,
            0
          );
        });
        it("fails transferring when recipient is not allowlisted", async function () {
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(this.token, recipient, partition1, 0);

          await expectRevert.unspecified(this.token.transferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));

          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(
            this.token,
            recipient,
            partition1,
            0
          );
        });
      });
      describe("operatorTransferByPartition", function () {
        it("transfers the requested amount when sender and recipient are allowlisted", async function () {
          await this.extension.addAllowlisted(this.token.address, recipient, {
            from: controller,
          });
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(this.token, recipient, partition1, 0);
          assert.equal(
            await this.token.allowanceByPartition(
              partition1,
              tokenHolder,
              operator
            ),
            0
          );

          const approvedAmount = 400;
          await this.token.approveByPartition(
            partition1,
            operator,
            approvedAmount,
            { from: tokenHolder }
          );
          assert.equal(
            await this.token.allowanceByPartition(
              partition1,
              tokenHolder,
              operator
            ),
            approvedAmount
          );
          await this.token.operatorTransferByPartition(
            partition1,
            tokenHolder,
            recipient,
            transferAmount,
            ZERO_BYTE,
            EMPTY_CERTIFICATE,
            { from: operator }
          );

          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount - transferAmount
          );
          await assertBalanceOf(
            this.token,
            recipient,
            partition1,
            transferAmount
          );
          assert.equal(
            await this.token.allowanceByPartition(
              partition1,
              tokenHolder,
              operator
            ),
            approvedAmount - transferAmount
          );
        });
      });
    });
    describe("ERC20 functions", function () {
      describe("transfer", function () {
        it("transfers the requested amount when sender and recipient are allowlisted", async function () {
          await this.extension.addAllowlisted(this.token.address, recipient, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.transfer(recipient, transferAmount, {
            from: tokenHolder,
          });

          await assertBalance(this.token, tokenHolder, issuanceAmount - transferAmount);
          await assertBalance(this.token, recipient, transferAmount);
        });
        it("fails transferring when sender and is not allowlisted", async function () {
          await this.extension.addAllowlisted(this.token.address, recipient, {
            from: controller,
          });
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await expectRevert.unspecified(
            this.token.transfer(recipient, transferAmount, {
              from: tokenHolder,
            })
          );

          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);
        });
        it("fails transferring when recipient and is not allowlisted", async function () {
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await expectRevert.unspecified(
            this.token.transfer(recipient, transferAmount, {
              from: tokenHolder,
            })
          );

          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);
        });
      });
      describe("transferFrom", function () {
        it("transfers the requested amount when sender and recipient are allowlisted", async function () {
          await this.extension.addAllowlisted(this.token.address, recipient, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await  this.token.transferFrom(tokenHolder, recipient, transferAmount, {
            from: operator,
          });

          await assertBalance(this.token, tokenHolder, issuanceAmount - transferAmount);
          await assertBalance(this.token, recipient, transferAmount);
        });
        it("fails transferring when sender is not allowlisted", async function () {
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await expectRevert.unspecified(
            this.token.transferFrom(tokenHolder, recipient, transferAmount, {
              from: operator,
            })
          );

          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);
        });
        it("fails transferring when recipient is not allowlisted", async function () {
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await expectRevert.unspecified(
            this.token.transferFrom(tokenHolder, recipient, transferAmount, {
              from: operator,
            })
          );

          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);
        });
        
      });
    });
  });

  // BLOCKLIST EXTENSION
  describe("blocklist", function () {
    const redeemAmount = 50;
    const transferAmount = 300;
    beforeEach(async function () {
      await assertTokenHasExtension(
        this.registry,
        this.extension,
        this.token,
      );

      await setCertificateActivated(
        this.extension,
        this.token,
        controller,
        CERTIFICATE_VALIDATION_NONE
      );

      await assertCertificateActivated(
        this.extension,
        this.token,
        CERTIFICATE_VALIDATION_NONE
      )

      await assertBlockListActivated(
        this.extension,
        this.token,
        true
      )

      await this.extension.addAllowlisted(this.token.address, tokenHolder, {
        from: controller,
      });

      await this.extension.addAllowlisted(this.token.address, recipient, {
        from: controller,
      });

      await this.token.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        EMPTY_CERTIFICATE,
        { from: controller }
      );
    });
    describe("ERC1400 functions", function () {
      describe("issue", function () {
        it("issues new tokens when recipient is not  blocklisted", async function () {
          await this.token.issue(
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: controller }
          );
          await assertTotalSupply(this.token, 2 * issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            2 * issuanceAmount
          );
        });
        it("issues new tokens when recipient is blocklisted, but blocklist is not activated", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await setBlockListActivated(
            this.extension,
            this.token,
            controller,
            false
          );
  
          await assertBlockListActivated(
            this.extension,
            this.token,
            false
          )
          await this.token.issue(
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: controller }
          );
          await assertTotalSupply(this.token, 2 * issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            2 * issuanceAmount
          );
        });
        it("fails issuing when recipient is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await this.extension.removeBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          }); // for coverage
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await expectRevert.unspecified(this.token.issue(
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: controller }
          ));
        });
      });
      describe("issueByPartition", function () {
        it("issues new tokens when recipient is not blocklisted", async function () {
          await this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: controller }
          );
          await assertTotalSupply(this.token, 2 * issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            2 * issuanceAmount
          );
        });
        it("fails issuing when recipient is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await expectRevert.unspecified(this.token.issueByPartition(
            partition1,
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: controller }
          ));
        });
      });
      describe("redeem", function () {
        it("redeeems the requested amount when sender is not blocklisted", async function () {
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);

          await this.token.redeem(issuanceAmount, EMPTY_CERTIFICATE, {
            from: tokenHolder,
          });

          await assertTotalSupply(this.token, 0);
          await assertBalance(this.token, tokenHolder, 0);
        });
        it("fails redeeming when sender is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);

          await expectRevert.unspecified(this.token.redeem(issuanceAmount, EMPTY_CERTIFICATE, {
            from: tokenHolder,
          }));

          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);
        });
      });
      describe("redeemFrom", function () {
        it("redeems the requested amount when sender is not blocklisted", async function () {
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await this.token.redeemFrom(
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          );

          await assertTotalSupply(this.token, 0);
          await assertBalance(this.token, tokenHolder, 0);
        });
        it("fails redeeming the requested amount when sender is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await expectRevert.unspecified(this.token.redeemFrom(
            tokenHolder,
            issuanceAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          ));

          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalance(this.token, tokenHolder, issuanceAmount);
        });
      });
      describe("redeemByPartition", function () {
        it("redeems the requested amount when sender is not blocklisted", async function () {
          await this.token.redeemByPartition(
            partition1,
            redeemAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );
          await assertTotalSupply(this.token, issuanceAmount - redeemAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount - redeemAmount
          );
        });
        it("fails redeems when sender is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await expectRevert.unspecified(this.token.redeemByPartition(
            partition1,
            redeemAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));
          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
        });
      });
      describe("operatorRedeemByPartition", function () {
        it("redeems the requested amount when sender is not blocklisted", async function () {
          await this.token.authorizeOperatorByPartition(partition1, operator, {
            from: tokenHolder,
          });
          await this.token.operatorRedeemByPartition(
            partition1,
            tokenHolder,
            redeemAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          );

          await assertTotalSupply(this.token, issuanceAmount - redeemAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount - redeemAmount
          );
        });
        it("fails redeeming when sender is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await this.token.authorizeOperatorByPartition(partition1, operator, {
            from: tokenHolder,
          });
          await expectRevert.unspecified(this.token.operatorRedeemByPartition(
            partition1,
            tokenHolder,
            redeemAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          ));

          await assertTotalSupply(this.token, issuanceAmount);
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
        });
      });
      describe("transferWithData", function () {
        it("transfers the requested amount when sender and recipient are not blocklisted", async function () {
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.transferWithData(
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );

          await assertBalance(
            this.token,
            tokenHolder,
            issuanceAmount - transferAmount
          );
          await assertBalance(this.token, recipient, transferAmount);
        });
        it("fails transferring when sender is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await expectRevert.unspecified(this.token.transferWithData(
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));

          await assertBalance(
            this.token,
            tokenHolder,
            issuanceAmount
          );
          await assertBalance(this.token, recipient, 0);
        });
        it("fails transferring when recipient is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, recipient, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await expectRevert.unspecified(this.token.transferWithData(
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));

          await assertBalance(
            this.token,
            tokenHolder,
            issuanceAmount
          );
          await assertBalance(this.token, recipient, 0);
        });
      });
      describe("transferFromWithData", function () {
        it("transfers the requested amount when sender and recipient are not blocklisted", async function () {
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await this.token.transferFromWithData(
            tokenHolder,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: operator }
          );

          await assertBalance(
            this.token,
            tokenHolder,
            issuanceAmount - transferAmount
          );
          await assertBalance(this.token, recipient, transferAmount);
        });
      });
      describe("transferByPartition", function () {
        it("transfers the requested amount when sender and recipient are not blocklisted", async function () {
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(this.token, recipient, partition1, 0);

          await this.token.transferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );

          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount - transferAmount
          );
          await assertBalanceOf(
            this.token,
            recipient,
            partition1,
            transferAmount
          );
        });
        it("fails transferring when sender is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(this.token, recipient, partition1, 0);

          await expectRevert.unspecified(this.token.transferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));

          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(
            this.token,
            recipient,
            partition1,
            0
          );
        });
        it("fails transferring when recipient is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, recipient, {
            from: controller,
          });
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(this.token, recipient, partition1, 0);

          await expectRevert.unspecified(this.token.transferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));

          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(
            this.token,
            recipient,
            partition1,
            0
          );
        });
      });
      describe("operatorTransferByPartition", function () {
        it("transfers the requested amount when sender and recipient are not blocklisted", async function () {
          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount
          );
          await assertBalanceOf(this.token, recipient, partition1, 0);
          assert.equal(
            await this.token.allowanceByPartition(
              partition1,
              tokenHolder,
              operator
            ),
            0
          );

          const approvedAmount = 400;
          await this.token.approveByPartition(
            partition1,
            operator,
            approvedAmount,
            { from: tokenHolder }
          );
          assert.equal(
            await this.token.allowanceByPartition(
              partition1,
              tokenHolder,
              operator
            ),
            approvedAmount
          );
          await this.token.operatorTransferByPartition(
            partition1,
            tokenHolder,
            recipient,
            transferAmount,
            ZERO_BYTE,
            EMPTY_CERTIFICATE,
            { from: operator }
          );

          await assertBalanceOf(
            this.token,
            tokenHolder,
            partition1,
            issuanceAmount - transferAmount
          );
          await assertBalanceOf(
            this.token,
            recipient,
            partition1,
            transferAmount
          );
          assert.equal(
            await this.token.allowanceByPartition(
              partition1,
              tokenHolder,
              operator
            ),
            approvedAmount - transferAmount
          );
        });
      });
    });
    describe("ERC20 functions", function () {
      describe("transfer", function () {
        it("transfers the requested amount when sender and recipient are not blocklisted", async function () {
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.transfer(recipient, transferAmount, {
            from: tokenHolder,
          });

          await assertBalance(this.token, tokenHolder, issuanceAmount - transferAmount);
          await assertBalance(this.token, recipient, transferAmount);
        });
        it("fails transferring when sender and is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await expectRevert.unspecified(
            this.token.transfer(recipient, transferAmount, {
              from: tokenHolder,
            })
          );

          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);
        });
        it("fails transferring when recipient is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, recipient, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await expectRevert.unspecified(
            this.token.transfer(recipient, transferAmount, {
              from: tokenHolder,
            })
          );

          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);
        });
      });
      describe("transferFrom", function () {
        it("transfers the requested amount when sender and recipient are not blocklisted", async function () {
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await  this.token.transferFrom(tokenHolder, recipient, transferAmount, {
            from: operator,
          });

          await assertBalance(this.token, tokenHolder, issuanceAmount - transferAmount);
          await assertBalance(this.token, recipient, transferAmount);
        });
        it("fails transferring when sender is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, tokenHolder, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await expectRevert.unspecified(
            this.token.transferFrom(tokenHolder, recipient, transferAmount, {
              from: operator,
            })
          );

          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);
        });
        it("fails transferring when recipient is blocklisted", async function () {
          await this.extension.addBlocklisted(this.token.address, recipient, {
            from: controller,
          });
          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);

          await this.token.authorizeOperator(operator, { from: tokenHolder });
          await expectRevert.unspecified(
            this.token.transferFrom(tokenHolder, recipient, transferAmount, {
              from: operator,
            })
          );

          await assertBalance(this.token, tokenHolder, issuanceAmount);
          await assertBalance(this.token, recipient, 0);
        });
        
      });
    });
  });

  // GRANULARITY EXTENSION
  describe("partition granularity", function () {
    const localGranularity = 10;
    const amount = 10 * localGranularity;

    beforeEach(async function () {
      await setCertificateActivated(
        this.extension,
        this.token,
        controller,
        CERTIFICATE_VALIDATION_NONE
      )
      await assertCertificateActivated(
        this.extension,
        this.token,
        CERTIFICATE_VALIDATION_NONE
      );

      await setAllowListActivated(
        this.extension,
        this.token,
        controller,
        false
      )
      await assertAllowListActivated(
        this.extension,
        this.token,
        false
      );

      await this.token.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        EMPTY_CERTIFICATE,
        { from: controller }
      );
      await this.token.issueByPartition(
        partition2,
        tokenHolder,
        issuanceAmount,
        EMPTY_CERTIFICATE,
        { from: controller }
      );
    });

    describe("when partition granularity is activated", function () {
      beforeEach(async function () {
        await assertGranularityByPartitionActivated(
          this.extension,
          this.token,
          true
        );
      });
      describe("when partition granularity is updated by a token controller", function () {
        it("updates the partition granularity", async function () {
          assert.equal(0, await this.extension.granularityByPartition(this.token.address, partition1));
          assert.equal(0, await this.extension.granularityByPartition(this.token.address, partition2));
          await this.extension.setGranularityByPartition(this.token.address, partition2, localGranularity, { from: controller });
          assert.equal(0, await this.extension.granularityByPartition(this.token.address, partition1));
          assert.equal(localGranularity, await this.extension.granularityByPartition(this.token.address, partition2));
        });
      });
      describe("when partition granularity is not updated by a token controller", function () {
        it("reverts", async function () {
          await expectRevert.unspecified(this.extension.setGranularityByPartition(this.token.address, partition2, localGranularity, { from: unknown }));
        });
      });
      describe("when partition granularity is defined", function () {
        beforeEach(async function () {
          assert.equal(0, await this.extension.granularityByPartition(this.token.address, partition1));
          assert.equal(0, await this.extension.granularityByPartition(this.token.address, partition2));
          await this.extension.setGranularityByPartition(this.token.address, partition2, localGranularity, { from: controller });
          assert.equal(0, await this.extension.granularityByPartition(this.token.address, partition1));
          assert.equal(localGranularity, await this.extension.granularityByPartition(this.token.address, partition2));
        });
        it("transfers the requested amount when higher than the granularity", async function () {
          await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount);
          await assertBalanceOfByPartition(this.token, recipient, partition1, 0);
          await assertBalanceOfByPartition(this.token, tokenHolder, partition2, issuanceAmount);
          await assertBalanceOfByPartition(this.token, recipient, partition2, 0);
  
          await this.token.transferByPartition(
            partition1,
            recipient,
            amount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );
          await this.token.transferByPartition(
            partition2,
            recipient,
            amount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );

          await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount-amount);
          await assertBalanceOfByPartition(this.token, recipient, partition1, amount);
          await assertBalanceOfByPartition(this.token, tokenHolder, partition2, issuanceAmount-amount);
          await assertBalanceOfByPartition(this.token, recipient, partition2, amount);
        });
        it("reverts when the requested amount when lower than the granularity", async function () {
          await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount);
          await assertBalanceOfByPartition(this.token, recipient, partition1, 0);
          await assertBalanceOfByPartition(this.token, tokenHolder, partition2, issuanceAmount);
          await assertBalanceOfByPartition(this.token, recipient, partition2, 0);
  
          await this.token.transferByPartition(
            partition1,
            recipient,
            1,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );
          await expectRevert.unspecified(this.token.transferByPartition(
            partition2,
            recipient,
            1,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          ));

          await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount-1);
          await assertBalanceOfByPartition(this.token, recipient, partition1, 1);
          await assertBalanceOfByPartition(this.token, tokenHolder, partition2, issuanceAmount);
          await assertBalanceOfByPartition(this.token, recipient, partition2, 0);
        });
      });
      describe("when partition granularity is not defined", function () {
        beforeEach(async function () {
          assert.equal(0, await this.extension.granularityByPartition(this.token.address, partition1));
          assert.equal(0, await this.extension.granularityByPartition(this.token.address, partition2));
        });
        it("transfers the requested amount", async function () {
          await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount);
          await assertBalanceOfByPartition(this.token, recipient, partition1, 0);
          await assertBalanceOfByPartition(this.token, tokenHolder, partition2, issuanceAmount);
          await assertBalanceOfByPartition(this.token, recipient, partition2, 0);
  
          await this.token.transferByPartition(
            partition1,
            recipient,
            1,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );
          await this.token.transferByPartition(
            partition2,
            recipient,
            1,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          );

          await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount-1);
          await assertBalanceOfByPartition(this.token, recipient, partition1, 1);
          await assertBalanceOfByPartition(this.token, tokenHolder, partition2, issuanceAmount-1);
          await assertBalanceOfByPartition(this.token, recipient, partition2, 1);
        });
      });
    });
    describe("when partition granularity is not activated", function () {
      beforeEach(async function () {
        await setGranularityByPartitionActivated(
          this.extension,
          this.token,
          controller,
          false
        );

        await assertGranularityByPartitionActivated(
          this.extension,
          this.token,
          false
        );
      });
      it("transfers the requested amount", async function () {
        await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount);
        await assertBalanceOfByPartition(this.token, recipient, partition1, 0);
        await assertBalanceOfByPartition(this.token, tokenHolder, partition2, issuanceAmount);
        await assertBalanceOfByPartition(this.token, recipient, partition2, 0);

        await this.token.transferByPartition(
          partition1,
          recipient,
          1,
          EMPTY_CERTIFICATE,
          { from: tokenHolder }
        );
        await this.token.transferByPartition(
          partition2,
          recipient,
          1,
          EMPTY_CERTIFICATE,
          { from: tokenHolder }
        );

        await assertBalanceOfByPartition(this.token, tokenHolder, partition1, issuanceAmount-1);
        await assertBalanceOfByPartition(this.token, recipient, partition1, 1);
        await assertBalanceOfByPartition(this.token, tokenHolder, partition2, issuanceAmount-1);
        await assertBalanceOfByPartition(this.token, recipient, partition2, 1);
      });
    });

  });

  // TRANSFERFROM
  describe("transferFrom", function () {
    const approvedAmount = 10000;
    beforeEach(async function () {
      await assertHoldsActivated(
        this.extension,
        this.token,
        true
      );

      const certificate = await craftCertificate(
        this.token.contract.methods.issueByPartition(
          partition1,
          tokenHolder,
          issuanceAmount,
          EMPTY_CERTIFICATE,
        ).encodeABI(),
        this.token,
        this.extension,
        this.clock, // this.clock
        controller
      )
      await this.token.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        certificate,
        { from: controller }
      );

      await this.extension.addAllowlisted(this.token.address, tokenHolder, { from: controller });
      await this.extension.addAllowlisted(this.token.address, recipient, { from: controller });
    });

    describe("when token allowlist is activated", function () {
      beforeEach(async function () {
        await assertAllowListActivated(
          this.extension,
          this.token,
          true
        );
      });
      describe("when the sender and the recipient are allowlisted", function () {
        beforeEach(async function () {
          assert.equal(
            await this.extension.isAllowlisted(this.token.address, tokenHolder),
            true
          );
          assert.equal(
            await this.extension.isAllowlisted(this.token.address, recipient),
            true
          );
        });
        describe("when the operator is approved", function () {
          beforeEach(async function () {
            await this.token.approve(operator, approvedAmount, {
              from: tokenHolder,
            });
          });
          describe("when the amount is a multiple of the granularity", function () {
            describe("when the recipient is not the zero address", function () {
              describe("when the sender has enough balance", function () {
                const amount = 500;

                it("transfers the requested amount", async function () {
                  await this.token.transferFrom(
                    tokenHolder,
                    recipient,
                    amount,
                    { from: operator }
                  );
                  await assertBalance(
                    this.token,
                    tokenHolder,
                    issuanceAmount - amount
                  );
                  await assertBalance(this.token, recipient, amount);

                  assert.equal(
                    await this.token.allowance(tokenHolder, operator),
                    approvedAmount - amount
                  );
                });

                it("emits a sent + a transfer event", async function () {
                  const { logs } = await this.token.transferFrom(
                    tokenHolder,
                    recipient,
                    amount,
                    { from: operator }
                  );

                  assert.equal(logs.length, 2);

                  assert.equal(logs[0].event, "Transfer");
                  assert.equal(logs[0].args.from, tokenHolder);
                  assert.equal(logs[0].args.to, recipient);
                  assert.equal(logs[0].args.value, amount);

                  assert.equal(logs[1].event, "TransferByPartition");
                  assert.equal(logs[1].args.fromPartition, partition1);
                  assert.equal(logs[1].args.operator, operator);
                  assert.equal(logs[1].args.from, tokenHolder);
                  assert.equal(logs[1].args.to, recipient);
                  assert.equal(logs[1].args.value, amount);
                  assert.equal(logs[1].args.data, null);
                  assert.equal(logs[1].args.operatorData, null);
                });
              });
              describe("when the sender does not have enough balance", function () {
                const amount = approvedAmount + 1;

                it("reverts", async function () {
                  await expectRevert.unspecified(
                    this.token.transferFrom(tokenHolder, recipient, amount, {
                      from: operator,
                    })
                  );
                });
              });
            });

            describe("when the recipient is the zero address", function () {
              const amount = issuanceAmount;

              it("reverts", async function () {
                await expectRevert.unspecified(
                  this.token.transferFrom(tokenHolder, ZERO_ADDRESS, amount, {
                    from: operator,
                  })
                );
              });
            });
          });
          describe("when the amount is not a multiple of the granularity", function () {
            it("reverts", async function () {
              this.token2 = await ERC1400HoldableCertificate.new(
                "ERC1400Token",
                "DAU",
                2,
                [controller],
                partitions,
                this.extension.address,
                owner,
                CERTIFICATE_SIGNER,
                CERTIFICATE_VALIDATION_DEFAULT,
                { from: controller }
              );
              const certificate = await craftCertificate(
                this.token2.contract.methods.issueByPartition(
                  partition1,
                  tokenHolder,
                  issuanceAmount,
                  EMPTY_CERTIFICATE,
                ).encodeABI(),
                this.token2,
                this.extension,
                this.clock, // this.clock
                controller
              )
              await this.token2.issueByPartition(
                partition1,
                tokenHolder,
                issuanceAmount,
                certificate,
                { from: controller }
              )

              await assertTokenHasExtension(
                this.registry,
                this.extension,
                this.token2,
              );
              await assertAllowListActivated(
                this.extension,
                this.token2,
                true
              );
      
              await this.extension.addAllowlisted(this.token2.address, tokenHolder, { from: controller });
              await this.extension.addAllowlisted(this.token2.address, recipient, { from: controller });

              await this.token2.approve(operator, approvedAmount, { from: tokenHolder });

              await expectRevert.unspecified(
                this.token2.transferFrom(tokenHolder, recipient, 3, {
                  from: operator,
                })
              );
            });
          });
        });
        describe("when the operator is not approved", function () {
          const amount = 100;
          describe("when the operator is not approved but authorized", function () {
            it("transfers the requested amount", async function () {
              await this.token.authorizeOperator(operator, {
                from: tokenHolder,
              });
              assert.equal(
                await this.token.allowance(tokenHolder, operator),
                0
              );

              await this.token.transferFrom(tokenHolder, recipient, amount, {
                from: operator,
              });

              await assertBalance(
                this.token,
                tokenHolder,
                issuanceAmount - amount
              );
              await assertBalance(this.token, recipient, amount);
            });
          });
          describe("when the operator is not approved and not authorized", function () {
            it("reverts", async function () {
              await expectRevert.unspecified(
                this.token.transferFrom(tokenHolder, recipient, amount, {
                  from: operator,
                })
              );
            });
          });
        });
      });
      describe("when the sender is not allowlisted", function () {
        const amount = approvedAmount;
        beforeEach(async function () {
          await this.extension.removeAllowlisted(this.token.address, tokenHolder, {
            from: controller,
          });

          assert.equal(
            await this.extension.isAllowlisted(this.token.address, tokenHolder),
            false
          );
          assert.equal(
            await this.extension.isAllowlisted(this.token.address, recipient),
            true
          );
        });
        it("reverts", async function () {
          await expectRevert.unspecified(
            this.token.transferFrom(tokenHolder, recipient, amount, {
              from: operator,
            })
          );
        });
      });
      describe("when the recipient is not allowlisted", function () {
        const amount = approvedAmount;
        beforeEach(async function () {
          await this.extension.removeAllowlisted(this.token.address, recipient, {
            from: controller,
          });

          assert.equal(
            await this.extension.isAllowlisted(this.token.address, tokenHolder),
            true
          );
          assert.equal(
            await this.extension.isAllowlisted(this.token.address, recipient),
            false
          );
        });
        it("reverts", async function () {
          await expectRevert.unspecified(
            this.token.transferFrom(tokenHolder, recipient, amount, {
              from: operator,
            })
          );
        });
      });
    });
  });

  // PAUSABLE EXTENSION
  describe("pausable", function () {
    const transferAmount = 300;

    beforeEach(async function () {
      const certificate = await craftCertificate(
        this.token.contract.methods.issueByPartition(
          partition1,
          tokenHolder,
          issuanceAmount,
          EMPTY_CERTIFICATE,
        ).encodeABI(),
        this.token,
        this.extension,
        this.clock, // this.clock
        controller
      )
      await this.token.issueByPartition(
        partition1,
        tokenHolder,
        issuanceAmount,
        certificate,
        { from: controller }
      );

      await setAllowListActivated(
        this.extension,
        this.token,
        controller,
        false
      )
      await assertAllowListActivated(
        this.extension,
        this.token,
        false
      );

      await setCertificateActivated(
        this.extension,
        this.token,
        controller,
        CERTIFICATE_VALIDATION_NONE
      )
      await assertCertificateActivated(
        this.extension,
        this.token,
        CERTIFICATE_VALIDATION_NONE
      );
    });

    describe("when contract is not paused", function () {
      beforeEach(async function () {
        await assertTokenHasExtension(
          this.registry,
          this.extension,
          this.token,
        );

        assert.equal(false, await this.extension.paused(this.token.address));
      });
      it("transfers the requested amount", async function () {
        await this.token.transfer(recipient, transferAmount, {
          from: tokenHolder,
        });
        await assertBalance(
          this.token,
          tokenHolder,
          issuanceAmount - transferAmount
        );
        await assertBalance(this.token, recipient, transferAmount);
      });
      it("transfers the requested amount (after pause/unpause)", async function () {
        assert.equal(false, await this.extension.paused(this.token.address));
        await this.extension.pause(this.token.address, { from: controller });
        await expectRevert.unspecified(
          this.extension.pause(this.token.address, { from: controller })
        );

        assert.equal(true, await this.extension.paused(this.token.address));
        await this.extension.unpause(this.token.address, { from: controller });
        await expectRevert.unspecified(
          this.extension.unpause(this.token.address, { from: controller })
        );

        assert.equal(false, await this.extension.paused(this.token.address));
        await this.token.transfer(recipient, transferAmount, {
          from: tokenHolder,
        });
        await assertBalance(
          this.token,
          tokenHolder,
          issuanceAmount - transferAmount
        );
        await assertBalance(this.token, recipient, transferAmount);
      });
      it("transfers the requested amount", async function () {
        await assertBalanceOf(
          this.token,
          tokenHolder,
          partition1,
          issuanceAmount
        );
        await assertBalanceOf(this.token, recipient, partition1, 0);

        await this.token.transferByPartition(
          partition1,
          recipient,
          transferAmount,
          EMPTY_CERTIFICATE,
          { from: tokenHolder }
        );
        await this.token.transferByPartition(
          partition1,
          recipient,
          0,
          EMPTY_CERTIFICATE,
          { from: tokenHolder }
        );

        await assertBalanceOf(
          this.token,
          tokenHolder,
          partition1,
          issuanceAmount - transferAmount
        );
        await assertBalanceOf(
          this.token,
          recipient,
          partition1,
          transferAmount
        );
      });
    });
    describe("when contract is paused", function () {
      beforeEach(async function () {
        await assertTokenHasExtension(
          this.registry,
          this.extension,
          this.token,
        );

        await this.extension.pause(this.token.address, { from: controller });

        assert.equal(true, await this.extension.paused(this.token.address));
      });
      it("reverts", async function () {
        await assertBalance(this.token, tokenHolder, issuanceAmount);
        await expectRevert.unspecified(
          this.token.transfer(recipient, issuanceAmount, { from: tokenHolder })
        );
      });
      it("reverts", async function () {
        await assertBalanceOf(
          this.token,
          tokenHolder,
          partition1,
          issuanceAmount
        );

        await expectRevert.unspecified(
          this.token.transferByPartition(
            partition1,
            recipient,
            transferAmount,
            EMPTY_CERTIFICATE,
            { from: tokenHolder }
          )
        );
      });
    });
  });

  // SET TOKEN CONTROLLERS
  describe("setTokenControllers", function () {
    describe("when the caller is the token contract owner", function () {
      it("sets the operators as token controllers", async function () {
        await assertIsTokenController(
          this.extension,
          this.token,
          controller,
          true,
        );

        await assertIsTokenController(
          this.extension,
          this.token,
          tokenController1,
          false,
        );
        await addTokenController(
          this.extension,
          this.token,
          owner,
          tokenController1
        );
        await assertIsTokenController(
          this.extension,
          this.token,
          tokenController1,
          true,
        );
      });
    });
    describe("when the caller is an other token controller", function () {
      it("sets the operators as token controllers", async function () {
        await assertIsTokenController(
          this.extension,
          this.token,
          controller,
          true,
        );

        await assertIsTokenController(
          this.extension,
          this.token,
          tokenController1,
          false,
        );
        await addTokenController(
          this.extension,
          this.token,
          owner,
          tokenController1
        );
        await assertIsTokenController(
          this.extension,
          this.token,
          tokenController1,
          true,
        );

        await assertIsTokenController(
          this.extension,
          this.token,
          tokenController2,
          false,
        );
        await addTokenController(
          this.extension,
          this.token,
          tokenController1,
          tokenController2
        );
        await assertIsTokenController(
          this.extension,
          this.token,
          tokenController2,
          true,
        );
      });
    });
    describe("when the caller is neither the token contract owner nor a token controller", function () {
      it("reverts", async function () {
        await expectRevert.unspecified(
          addTokenController(
            this.extension,
            this.token,
            unknown,
            tokenController1
          )
        );
      });
    });
  });
});