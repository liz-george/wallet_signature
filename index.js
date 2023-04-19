const { ethers } = require('ethers');
const {
    keccak256
} = require("@ethersproject/keccak256");
const abi = require('ethereumjs-abi');
const { defaultAbiCoder } = require('ethers/lib/utils');
const Dotenv = require('dotenv');
Dotenv.config({
  silent: true,
});

async function run() {
  // Load the private key 
  const privateKey = process.env.PRIVATE_KEY;

  // Get the chainId : mainnet 1
  const chainId = process.env.CHAIN_ID;

  // Generate a random nonce value for each message
  const nonce = Math.floor(Math.random() * 1000000);

  // Define the domain separator 
  const domainSeparator = getDomainSeparator(chainId);

  // Define the message types
  const messageTypes = getMessageTypes();

  // Define the message
  const message = {
    platformName: 'Vow wallet',
    chainId: chainId,
    timestamp: Math.floor(Date.now() / 1000),
    nonce: nonce
  };

  // Hash the message
  const messageHash = getMessageHash(message, domainSeparator, messageTypes);

  // Sign the message hash
  const signingKey = new ethers.utils.SigningKey(privateKey);
  const signature = signingKey.signDigest(messageHash);

  console.log('signature', signature);

  /**
   * Example sample for signature : 
   
    signature { 
    r: '0x70b6a120bdfba4e661aa6d0a0e93b974eec04c21044d213f7549fecc111f0224',
    s: '0x426eed31356c9aa1a62eab4e2849aa4fbf36d9ae7ef4c4f8b4998000845c3ea1',
    _vs: '0x426eed31356c9aa1a62eab4e2849aa4fbf36d9ae7ef4c4f8b4998000845c3ea1',
    recoveryParam: 0,
    v: 27,
    yParityAndS: '0x426eed31356c9aa1a62eab4e2849aa4fbf36d9ae7ef4c4f8b4998000845c3ea1',
    compact: '0x70b6a120bdfba4e661aa6d0a0e93b974eec04c21044d213f7549fecc111f0224426eed31356c9aa1a62eab4e2849aa4fbf36d9ae7ef4c4f8b4998000845c3ea1'
    }
   */

  // Verify the signature
  const recoveredAddress = ethers.utils.recoverAddress(
    messageHash,
    signature
  );
  console.log('recoveredAddress', recoveredAddress);

  if (recoveredAddress === '0xc430587dec0bbc4bF5232E30b652324D63E4b910') {
    console.log('Signature verified');
  } else {
    console.log('Invalid signature');
  }
}

function getDomainSeparator(chainId) {
  const domain = {
    name: 'Vow wallet',
    version: '1',
    chainId: chainId,
    verifyingContract: '0x0000000000000000000000000000000000000000',
  };
  return keccak256(
    defaultAbiCoder.encode(
      ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
      [
        keccak256(Buffer.from('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')),
        keccak256(Buffer.from(domain.name)),
        keccak256(Buffer.from(domain.version)),
        domain.chainId,
        domain.verifyingContract,
      ]
    )
  );
}

function getMessageTypes() {
  return {
    VerifyUser: [
      { name: 'platformName', type: 'string' },
      { name: 'chainId', type: 'uint256' },
      { name: 'timestamp', type: 'uint256' },
      { name: 'nonce', type: 'uint256' }
    ]
  };
}

function getMessageHash(message, domainSeparator, messageTypes) {
  return ethers.utils.solidityKeccak256(
    ['bytes1', 'bytes1', 'bytes32', 'bytes32'],
    [
      '0x19',
      '0x01',
      domainSeparator,
      ethers.utils.solidityKeccak256(
        ['bytes32', ...messageTypes.VerifyUser.map(({ type }) => type)],
        [
          ethers.utils.keccak256(
            ethers.utils.toUtf8Bytes('VerifyUser(string platformName,uint256 chainId,uint256 timestamp,uint256 nonce)')
          ),
          message.platformName,
          message.chainId,
          message.timestamp,
          message.nonce
        ]
      )
    ]
  );
}
run()