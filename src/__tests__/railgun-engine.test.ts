import chai, { expect } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { Contract, TransactionReceipt, Wallet } from 'ethers';
import memdown from 'memdown';
import { groth16 } from 'snarkjs';
import sinon, { SinonStub } from 'sinon';
import { RailgunEngine } from '../railgun-engine';
import { abi as erc20Abi } from '../test/test-erc20-abi.test';
import { config } from '../test/config.test';
import { abi as erc721Abi } from '../test/test-erc721-abi.test';
import { RailgunWallet } from '../wallet/railgun-wallet';
import {
  awaitMultipleScans,
  awaitScan,
  DECIMALS_18,
  getEthersWallet,
  mockGetLatestValidatedRailgunTxid,
  mockQuickSyncEvents,
  mockQuickSyncRailgunTransactions,
  mockRailgunTxidMerklerootValidator,
  sendTransactionWithLatestNonce,
  testArtifactsGetter,
} from '../test/helper.test';
import { ShieldNoteERC20 } from '../note/erc20/shield-note-erc20';
import {
  ByteLength,
  formatToByteLength,
  hexToBigInt,
  hexToBytes,
  nToHex,
  randomHex,
} from '../utils/bytes';
import { RailgunSmartWalletContract } from '../contracts/railgun-smart-wallet/railgun-smart-wallet';
import {
  CommitmentType,
  LegacyGeneratedCommitment,
  NFTTokenData,
  OutputType,
  RailgunTransaction,
  TokenType,
} from '../models/formatted-types';
import { SnarkJSGroth16 } from '../prover/prover';
import { TestERC20 } from '../test/abi/typechain/TestERC20';
import { TestERC721 } from '../test/abi/typechain/TestERC721';
import { promiseTimeout } from '../utils/promises';
import { Chain, ChainType } from '../models/engine-types';
import { TransactNote } from '../note/transact-note';
import { MEMO_SENDER_RANDOM_NULL, TOKEN_SUB_ID_NULL } from '../models/transaction-constants';
import { getTokenDataERC20, getTokenDataHash, getTokenDataNFT } from '../note/note-util';
import { TransactionBatch } from '../transaction/transaction-batch';
import { UnshieldNoteNFT } from '../note/nft/unshield-note-nft';
import { ContractStore } from '../contracts/contract-store';
import { mintNFTsID01ForTest, shieldNFTForTest } from '../test/shared-test.test';
import { createPollingJsonRpcProviderForListeners } from '../provider/polling-util';
import { isDefined } from '../utils/is-defined';
import { PollingJsonRpcProvider } from '../provider/polling-json-rpc-provider';
import { UTXOMerkletree } from '../merkletree/utxo-merkletree';
import { POI, POIListType } from '../poi/poi';
import { MOCK_LIST_KEY, TestPOINodeInterface } from '../test/test-poi-node-interface.test';
import { hashBoundParams } from '../transaction/bound-params';
import { createRailgunTransactionWithID } from '../transaction/railgun-txid';
import { RailgunTxidMerkletree } from '../merkletree/railgun-txid-merkletree';
import {
  POIEngineProofInputs,
  POIEngineProofInputsWithListPOIData,
  TXIDVersion,
} from '../models/poi-types';
import { getBlindedCommitmentForShield } from '../poi/blinded-commitment';
import { getShieldRailgunTxid } from '../poi/shield-railgun-txid';
import { getDummyPOIProofInputs } from '../test/test-poi-proof.test';
import { ShieldNote } from '../note';
import { TransactionStruct } from '../models';
import { AES } from '../utils';

chai.use(chaiAsPromised);

const txidVersion = TXIDVersion.V2_PoseidonMerkle;

let provider: PollingJsonRpcProvider;
let chain: Chain;
let engine: RailgunEngine;
let ethersWallet: Wallet;
let snapshot: number;
let token: TestERC20;
let nft: TestERC721;
let wallet: RailgunWallet;
let wallet2: RailgunWallet;
let utxoMerkletree: UTXOMerkletree;
let txidMerkletree: RailgunTxidMerkletree;
let tokenAddress: string;
let railgunSmartWalletContract: RailgunSmartWalletContract;

let transactNoteRandomStub: SinonStub;
let transactSenderRandomStub: SinonStub;
let aesGetRandomIVStub: SinonStub;

const erc20Address = config.contracts.rail;
const nftAddress = config.contracts.testERC721;

const testMnemonic = config.mnemonic;
const testEncryptionKey = config.encryptionKey;

const random = '67c600e777b86d3a1e72a53092e9fe85';

const shieldTestTokens = async (
  railgunAddress: string,
  value: bigint,
): Promise<ShieldNoteERC20> => {
  const mpk = RailgunEngine.decodeAddress(railgunAddress).masterPublicKey;
  const receiverViewingPublicKey = wallet.getViewingKeyPair().pubkey;
  const shield = new ShieldNoteERC20(mpk, random, value, await token.getAddress());

  const shieldPrivateKey = hexToBytes(randomHex(32));
  const shieldInput = await shield.serialize(shieldPrivateKey, receiverViewingPublicKey);

  // Create shield
  const shieldTx = await railgunSmartWalletContract.generateShield([shieldInput]);

  // Send shield on chain
  const tx = await sendTransactionWithLatestNonce(ethersWallet, shieldTx);
  await Promise.all([
    tx.wait(),
    promiseTimeout(awaitScan(wallet, chain), 10000, 'Timed out scanning after test token shield'),
  ]);
  return shield;
};

const generateAndVerifyPOI = async (
  shield: ShieldNoteERC20,
  transactReceipt: TransactionReceipt,
  transactions: TransactionStruct[],
  expectedProofInputs: POIEngineProofInputs,
  expectedBlindedCommitmentsOut: string[],
) => {
  const submitPOISpy = sinon.spy(TestPOINodeInterface.prototype, 'generateAndSubmitPOI');

  try {
    // No railgunTxid yet - no POI submitted.
    await wallet.generatePOIsAllSentCommitmentsAndUnshieldEvents(chain, txidVersion);
    expect(submitPOISpy.getCalls()).to.deep.equal([]);

    const { blockNumber } = transactReceipt;

    // eslint-disable-next-line no-restricted-syntax
    for (const transaction of transactions) {
      const railgunTransaction: RailgunTransaction = {
        graphID: '0x01',
        commitments: transaction.commitments as string[],
        nullifiers: transaction.nullifiers as string[],
        boundParamsHash: nToHex(hashBoundParams(transactions[0].boundParams), ByteLength.UINT_256),
        blockNumber,
        utxoTreeIn: undefined,
        globalStartPositionOut: undefined,
      };
      const railgunTransactionWithTxid = createRailgunTransactionWithID(
        railgunTransaction,
        txidVersion,
      );

      // eslint-disable-next-line no-await-in-loop
      await engine.handleNewRailgunTransactions(txidVersion, chain, [railgunTransactionWithTxid]);
    }

    // To debug POI Status Info:
    // await wallet.refreshSpentPOIsAllSentCommitmentsAndUnshieldEvents(chain);
    // console.log(await wallet.getTXOsReceivedPOIStatusInfo(chain));
    // console.log(await wallet.getTXOsSpentPOIStatusInfo(chain));

    await wallet.generatePOIsAllSentCommitmentsAndUnshieldEvents(chain, txidVersion);

    const calls = submitPOISpy.getCalls();
    expect(calls.length).to.equal(1);

    const firstCallArgs = submitPOISpy.getCalls()[0].args;

    const shieldCommitment = nToHex(
      ShieldNote.getShieldNoteHash(
        shield.notePublicKey,
        shield.tokenHash,
        BigInt('109725000000000000000000'),
      ),
      ByteLength.UINT_256,
    );
    const blindedCommitmentForShield = getBlindedCommitmentForShield(
      shieldCommitment,
      shield.notePublicKey,
      getShieldRailgunTxid(0, 0),
    );
    expect(blindedCommitmentForShield).to.equal(
      '0x1add5dfd0299e9dc5af6fdfc0d86c0aaad29f9f9ca61674f67d3d185e28802e2',
    );

    const expectedArgs: [
      chain: Chain,
      listKey: string,
      proofInputs: POIEngineProofInputs,
      blindedCommitmentsOut: string[],
      txidMerklerootIndex: number,
      railgunTransactionBlockNumber: number,
      txidVersion: TXIDVersion,
    ] = [
      chain,
      MOCK_LIST_KEY,
      expectedProofInputs,
      expectedBlindedCommitmentsOut,
      0, // txid merkleroot index
      blockNumber,
      TXIDVersion.V2_PoseidonMerkle,
    ];

    expect(firstCallArgs).to.deep.equal(expectedArgs);

    // Generate and verify POI proof with snarkjs
    const proofInputs: POIEngineProofInputs = expectedArgs[2];
    const blindedCommitmentsOut: string[] = expectedArgs[3];
    const fullProofInputs: POIEngineProofInputsWithListPOIData =
      getDummyPOIProofInputs(proofInputs);

    await engine.prover.provePOI(fullProofInputs, blindedCommitmentsOut, () => {});

    submitPOISpy.restore();
  } catch (err) {
    submitPOISpy.restore();
    throw err;
  }
};

describe('RailgunEngine', function test() {
  this.timeout(20000);

  beforeEach(async () => {
    engine = RailgunEngine.initForWallet(
      'Test Wallet',
      memdown(),
      testArtifactsGetter,
      mockQuickSyncEvents,
      mockQuickSyncRailgunTransactions,
      mockRailgunTxidMerklerootValidator,
      mockGetLatestValidatedRailgunTxid,
      undefined, // engineDebugger
      undefined, // skipMerkletreeScans
    );
    engine.prover.setSnarkJSGroth16(groth16 as SnarkJSGroth16);

    POI.init([{ key: MOCK_LIST_KEY, type: POIListType.Gather }], new TestPOINodeInterface());

    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      return;
    }

    transactNoteRandomStub = sinon
      .stub(TransactNote, 'getNoteRandom')
      .returns('123456789012345678901234567890ab'); // 16 bytes
    transactSenderRandomStub = sinon
      .stub(TransactNote, 'getSenderRandom')
      .returns('098765432109876543210987654321'); // 15 bytes
    aesGetRandomIVStub = sinon.stub(AES, 'getRandomIV').returns('abcdef1234567890abcdef1234567890');

    // EngineDebug.init(console); // uncomment for logs
    provider = new PollingJsonRpcProvider(config.rpc, config.chainId);
    chain = {
      type: ChainType.EVM,
      id: Number((await provider.getNetwork()).chainId),
    };

    ethersWallet = getEthersWallet(config.mnemonic, provider);

    snapshot = (await provider.send('evm_snapshot', [])) as number;
    token = new Contract(erc20Address, erc20Abi, ethersWallet) as unknown as TestERC20;
    tokenAddress = formatToByteLength(erc20Address, ByteLength.UINT_256, false);

    nft = new Contract(nftAddress, erc721Abi, ethersWallet) as unknown as TestERC721;

    const balance = await token.balanceOf(ethersWallet.address);
    await token.approve(config.contracts.proxy, balance);

    wallet = await engine.createWalletFromMnemonic(testEncryptionKey, testMnemonic);
    wallet2 = await engine.createWalletFromMnemonic(testEncryptionKey, testMnemonic, 1);
    const pollingProvider = await createPollingJsonRpcProviderForListeners(provider);
    await engine.loadNetwork(
      chain,
      config.contracts.proxy,
      config.contracts.relayAdapt,
      provider,
      pollingProvider,
      { [TXIDVersion.V2_PoseidonMerkle]: 24 },
      0,
    );
    await engine.scanHistory(chain);
    utxoMerkletree = engine.getUTXOMerkletreeForChain(txidVersion, chain);
    txidMerkletree = engine.getRailgunTxidMerkletreeForChain(txidVersion, chain);
    railgunSmartWalletContract = ContractStore.railgunSmartWalletContracts[chain.type][chain.id];
  });

  it('[HH] Should load existing wallets', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    engine.unloadWallet(wallet.id);
    await engine.loadExistingWallet(testEncryptionKey, wallet.id);
    expect(engine.wallets[wallet.id].id).to.equal(wallet.id);
  });

  it('Should delete wallet', async () => {
    const walletForDeletion = await engine.createWalletFromMnemonic(
      testEncryptionKey,
      testMnemonic,
      5, // index
    );

    await engine.deleteWallet(walletForDeletion.id);
    await expect(
      engine.loadExistingWallet(testEncryptionKey, walletForDeletion.id),
    ).to.be.rejectedWith(
      'Key not found in database [000000000000000000000000000000000000000000000000000077616c6c6574:4e562d7b2e7cd11d98309031e1697540b51647fa67c9621f74bbd8ef45312443]',
    );
  });

  it('[HH] Should get balances after shield and rescan', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    const shieldsPre = await engine.getAllShieldCommitments(txidVersion, chain, 0);
    expect(shieldsPre.length).to.equal(0);

    const commitment: LegacyGeneratedCommitment = {
      commitmentType: CommitmentType.LegacyGeneratedCommitment,
      hash: '14308448bcb19ecff96805fe3d00afecf82b18fa6f8297b42cf2aadc23f412e6',
      txid: '0x0543be0699a7eac2b75f23b33d435aacaeb0061f63e336230bcc7559a1852f33',
      timestamp: undefined,
      preImage: {
        npk: '0xc24ea33942c0fb9acce5dbada73137ad3257a6f2e1be8f309c1fe9afc5410a',
        token: {
          tokenType: TokenType.ERC20,
          tokenAddress: `0x${tokenAddress}`,
          tokenSubID: TOKEN_SUB_ID_NULL,
        },
        value: '9138822709a9fc231cba6',
      },
      encryptedRandom: [
        '0xb47a353e294711ff73cf086f97ee1ed29b853b67c353bc2371b87fe72c716cc6',
        '0x3d321af08b8fa7a8f70379407706b752',
      ],
      blockNumber: 0,
      utxoTree: 0,
      utxoIndex: 0,
    };

    // Override root validator
    utxoMerkletree.merklerootValidator = () => Promise.resolve(true);
    await utxoMerkletree.queueLeaves(0, 0, [commitment]);
    await utxoMerkletree.updateTreesFromWriteQueue();

    await wallet.scanBalances(txidVersion, chain, undefined);
    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    const value = hexToBigInt(commitment.preImage.value);
    expect(balance).to.equal(value);

    await wallet.fullRescanBalances(txidVersion, chain, undefined);
    const balanceRescan = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(balanceRescan).to.equal(value);

    await wallet.clearScannedBalances(txidVersion, chain);
    const balanceClear = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(balanceClear).to.equal(undefined);

    const shieldsPost = await engine.getAllShieldCommitments(txidVersion, chain, 0);
    expect(shieldsPost.length).to.equal(1);
  });

  it('[HH] With a creation block number provided, should show balance after shield and rescan', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    // [[chain.type]: [[chain.id]: 0]]
    const creationBlockNumbers: number[][] = [];
    creationBlockNumbers[chain.type] = [];
    creationBlockNumbers[chain.type][chain.id] = 0;
    wallet.setCreationBlockNumbers(creationBlockNumbers);

    const commitment: LegacyGeneratedCommitment = {
      commitmentType: CommitmentType.LegacyGeneratedCommitment,
      hash: '14308448bcb19ecff96805fe3d00afecf82b18fa6f8297b42cf2aadc23f412e6',
      txid: '0x0543be0699a7eac2b75f23b33d435aacaeb0061f63e336230bcc7559a1852f33',
      timestamp: undefined,
      preImage: {
        npk: '0xc24ea33942c0fb9acce5dbada73137ad3257a6f2e1be8f309c1fe9afc5410a',
        token: {
          tokenType: TokenType.ERC20,
          tokenAddress: `0x${tokenAddress}`,
          tokenSubID: TOKEN_SUB_ID_NULL,
        },
        value: '9138822709a9fc231cba6',
      },
      encryptedRandom: [
        '0xb47a353e294711ff73cf086f97ee1ed29b853b67c353bc2371b87fe72c716cc6',
        '0x3d321af08b8fa7a8f70379407706b752',
      ],
      blockNumber: 0,
      utxoTree: 0,
      utxoIndex: 0,
    };
    // Override root validator
    utxoMerkletree.merklerootValidator = () => Promise.resolve(true);
    await utxoMerkletree.queueLeaves(0, 0, [commitment]);
    await utxoMerkletree.updateTreesFromWriteQueue();

    await wallet.scanBalances(txidVersion, chain, undefined);
    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    const value = hexToBigInt(commitment.preImage.value);
    expect(balance).to.equal(value);

    const walletDetails = await wallet.getWalletDetails(txidVersion, chain);
    expect(walletDetails.creationTree).to.equal(0);
    expect(walletDetails.creationTreeHeight).to.equal(0);

    await wallet.fullRescanBalances(txidVersion, chain, undefined);
    const balanceRescan = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(balanceRescan).to.equal(value);

    await wallet.clearScannedBalances(txidVersion, chain);
    const balanceCleared = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(balanceCleared).to.equal(undefined);

    const walletDetailsCleared = await wallet.getWalletDetails(txidVersion, chain);
    expect(walletDetailsCleared.creationTree).to.equal(0); // creationTree should not get reset on clear
    expect(walletDetailsCleared.creationTreeHeight).to.equal(0); // creationTreeHeight should not get reset on clear
    expect(walletDetailsCleared.treeScannedHeights.length).to.equal(0);
  });

  it('[HH] Should shield, unshield w/ relayer and update balance, generate POIs, and pull formatted spend/receive transaction history', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    const initialBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(initialBalance).to.equal(undefined);

    const address = wallet.getAddress(chain);
    const shield = await shieldTestTokens(address, BigInt(110000) * DECIMALS_18);

    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(balance).to.equal(BigInt('109725000000000000000000'));

    const tokenData = getTokenDataERC20(tokenAddress);

    // Create transaction
    const transactionBatch = new TransactionBatch(chain);
    transactionBatch.addUnshieldData({
      toAddress: ethersWallet.address,
      value: BigInt(300) * DECIMALS_18,
      tokenData,
    });

    // Add output for mock Relayer
    transactionBatch.addOutput(
      TransactNote.createTransfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        1n,
        tokenData,
        wallet.getViewingKeyPair(),
        false, // showSenderAddressToRecipient
        OutputType.RelayerFee,
        undefined, // memoText
      ),
    );

    const transactions = await transactionBatch.generateTransactions(
      engine.prover,
      wallet,
      txidVersion,
      testEncryptionKey,
      () => {},
    );
    const transact = await railgunSmartWalletContract.transact(transactions);

    const transactTx = await sendTransactionWithLatestNonce(ethersWallet, transact);
    const transactReceipt = await transactTx.wait();
    if (!transactReceipt) {
      throw new Error('Failed to get transact receipt');
    }
    await Promise.all([
      promiseTimeout(awaitMultipleScans(wallet, chain, 2), 15000, 'Timed out wallet1 scan'),
      promiseTimeout(awaitMultipleScans(wallet2, chain, 2), 15000, 'Timed out wallet2 scan'),
    ]);

    // BALANCE = shielded amount - 300(decimals) - 1
    const newBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(newBalance).to.equal(109424999999999999999999n, 'Failed to receive expected balance');

    const newBalance2 = await wallet2.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(newBalance2).to.equal(BigInt(1));

    // Generate POI
    await generateAndVerifyPOI(
      shield,
      transactReceipt,
      transactions,
      {
        anyRailgunTxidMerklerootAfterTransaction:
          '1783f3970838a0586e95a73dd9b0cc96cffcb0d6a97ba343cfb277be7b1f8ac1',
        blindedCommitmentsIn: [
          '0x1add5dfd0299e9dc5af6fdfc0d86c0aaad29f9f9ca61674f67d3d185e28802e2',
        ],
        boundParamsHash: '0357cc6d8af845f638fb6e2bdbf482f466d11454a2e31c69d9b7ec69ce8cd873',
        commitmentsOut: [
          '0x2c5acad8f41f95a2795997353f6cdb0838493cd5604f8ddc1859a468233e15ac',
          '0x0c3f2e70ce66ea83593e26e7d13bd27a2a770920964786eaed95551b4ad51c4e',
          '0x05b93bb7d3cd650232f233868e9a420f08031029720f69df51dd04c6b7e5bd70',
        ],
        creationTxidsIn: ['0000000000000000000000000000000000000000000000000000000000000000'],
        npksOut: [
          2800314339815912641032015410982157821342520564864853273055282304996901162130n,
          11534906831940272621633961845961479374350832633003460590301493842374950642962n,
          1390849295786071768276380950238675083608645509734n,
        ],
        nullifiers: ['0x05802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee'],
        nullifyingKey:
          8368299126798249740586535953124199418524409103803955764525436743456763691384n,
        railgunTxidMerkleProofIndices:
          '0000000000000000000000000000000000000000000000000000000000000000',
        railgunTxidMerkleProofPathElements: [
          '0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc',
          '01c405064436affeae1fc8e30b2e417b4243bbb819adca3b55bb32efc3e43a4f',
          '0888d37652d10d1781db54b70af87b42a2916e87118f507218f9a42a58e85ed2',
          '183f531ead7217ebc316b4c02a2aad5ad87a1d56d4fb9ed81bf84f644549eaf5',
          '093c48f1ecedf2baec231f0af848a57a76c6cf05b290a396707972e1defd17df',
          '1437bb465994e0453357c17a676b9fdba554e215795ebc17ea5012770dfb77c7',
          '12359ef9572912b49f44556b8bbbfa69318955352f54cfa35cb0f41309ed445a',
          '2dc656dadc82cf7a4707786f4d682b0f130b6515f7927bde48214d37ec25a46c',
          '2500bdfc1592791583acefd050bc439a87f1d8e8697eb773e8e69b44973e6fdc',
          '244ae3b19397e842778b254cd15c037ed49190141b288ff10eb1390b34dc2c31',
          '0ca2b107491c8ca6e5f7e22403ea8529c1e349a1057b8713e09ca9f5b9294d46',
          '18593c75a9e42af27b5e5b56b99c4c6a5d7e7d6e362f00c8e3f69aeebce52313',
          '17aca915b237b04f873518947a1f440f0c1477a6ac79299b3be46858137d4bfb',
          '2726c22ad3d9e23414887e8233ee83cc51603f58c48a9c9e33cb1f306d4365c0',
          '08c5bd0f85cef2f8c3c1412a2b69ee943c6925ecf79798bb2b84e1b76d26871f',
          '27f7c465045e0a4d8bec7c13e41d793734c50006ca08920732ce8c3096261435',
        ],
        randomsIn: ['67c600e777b86d3a1e72a53092e9fe85'],
        spendingPublicKey: [
          15684838006997671713939066069845237677934334329285343229142447933587909549584n,
          11878614856120328179849762231924033298788609151532558727282528569229552954628n,
        ],
        token: '0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0',
        utxoPositionsIn: [0],
        utxoTreesIn: 0,
        valuesIn: [109725000000000000000000n],
        valuesOut: [1n, 109424999999999999999999n, 300000000000000000000n],
      },
      [
        '0x0182d195e53265b697cfe4fff30f20459890431f196159479223913a1ad3c98c',
        '0x0ae160c53e834a2c886a05204a096339979f7a0a33fe5d63eafc42386c399504',
        '0x17b247216cd083631406631e76c9e052a74fadb38a029b7243784f519251c115',
      ],
    );

    // check the transactions log
    const history = await wallet.getTransactionHistory(chain, undefined);
    expect(history.length).to.equal(2);

    const tokenFormatted = formatToByteLength(tokenAddress, ByteLength.UINT_256, false);

    // Make sure nullifier events map to completed txid.
    const nullifiers = transactions.map((transaction) => transaction.nullifiers).flat() as string[];
    const completedTxid = await engine.getCompletedTxidFromNullifiers(
      TXIDVersion.V2_PoseidonMerkle,
      chain,
      nullifiers,
    );
    expect(completedTxid).to.equal(transactTx.hash);

    // Check first output: Shield (receive only).
    expect(history[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109725000000000000000000'),
        memoText: undefined,
        senderAddress: undefined,
        shieldFee: '275000000000000000000',
      },
    ]);
    expect(history[0].transferTokenAmounts).deep.eq([]);
    expect(history[0].relayerFeeTokenAmount).eq(undefined);
    expect(history[0].changeTokenAmounts).deep.eq([]);
    expect(history[0].unshieldTokenAmounts).deep.eq([]);

    // Check second output: Unshield (relayer fee + change).
    // NOTE: No receive token amounts should be logged by history.

    // TODO: The stubs for sinon random cause this expectation to fail:
    // expect(history[1].receiveTokenAmounts).deep.eq(
    //   [],
    //   "Receive amount should be filtered out - it's the same as change output.",
    // );

    expect(history[1].transferTokenAmounts).deep.eq([]);
    expect(history[1].relayerFeeTokenAmount).deep.eq({
      tokenData: getTokenDataERC20(tokenAddress),
      tokenHash: tokenFormatted,
      amount: BigInt(1),
      noteAnnotationData: {
        outputType: OutputType.RelayerFee,
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        senderRandom: history[1].relayerFeeTokenAmount!.noteAnnotationData!.senderRandom,
        walletSource: 'test wallet',
      },
      memoText: undefined,
    });
    expect(history[1].changeTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109424999999999999999999'),
        noteAnnotationData: {
          outputType: OutputType.Change,
          senderRandom: MEMO_SENDER_RANDOM_NULL,
          walletSource: 'test wallet',
        },
        memoText: undefined,
      },
    ]);
    expect(history[1].unshieldTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('299250000000000000000'), // 300 minus fee
        recipientAddress: ethersWallet.address,
        memoText: undefined,
        senderAddress: undefined,
        unshieldFee: '750000000000000000',
      },
    ]);

    // Check that no history exists for a high starting block.
    const historyHighStartingBlock = await wallet.getTransactionHistory(chain, 10000000);
    expect(historyHighStartingBlock.length).to.equal(0);
  }).timeout(90000);

  it('[HH] Should shield, max-unshield without relayer, generate POIs, and pull formatted spend/receive transaction history', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    const initialBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(initialBalance).to.equal(undefined);

    const address = wallet.getAddress(chain);
    const shield = await shieldTestTokens(address, BigInt(110000) * DECIMALS_18);

    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(balance).to.equal(BigInt('109725000000000000000000'));

    const tokenData = getTokenDataERC20(tokenAddress);

    // Create transaction
    const transactionBatch = new TransactionBatch(chain);
    transactionBatch.addUnshieldData({
      toAddress: ethersWallet.address,
      value: BigInt('109725000000000000000000'),
      tokenData,
    });

    const transactions = await transactionBatch.generateTransactions(
      engine.prover,
      wallet,
      txidVersion,
      testEncryptionKey,
      () => {},
    );
    expect(transactions.length).to.equal(1);
    expect(transactions[0].nullifiers.length).to.equal(1);
    expect(transactions[0].commitments.length).to.equal(1);
    const transact = await railgunSmartWalletContract.transact(transactions);

    const transactTx = await sendTransactionWithLatestNonce(ethersWallet, transact);
    const [transactReceipt] = await Promise.all([
      transactTx.wait(),
      promiseTimeout(awaitScan(wallet, chain), 15000, 'Timed out wallet1 scan'),
    ]);
    if (!transactReceipt) {
      throw new Error('No transaction receipt');
    }

    const newBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(newBalance).to.equal(0n, 'Failed to receive expected balance');

    // Generate POI
    await generateAndVerifyPOI(
      shield,
      transactReceipt,
      transactions,
      {
        anyRailgunTxidMerklerootAfterTransaction:
          '00982696ece890aea23f350bcb75a6e65fc8844b50607ee1e685317588d6bcce',
        blindedCommitmentsIn: [
          '0x1add5dfd0299e9dc5af6fdfc0d86c0aaad29f9f9ca61674f67d3d185e28802e2',
        ],
        boundParamsHash: '0a4e7bed8287c629fd064665543dc71fdc09b0ab9df7d556f24a1f2f9f018dc7',
        commitmentsOut: ['0x007aaf0cbee05066820873170e293e44df6766c29da69ac46fd05d4ff2c0a225'],
        creationTxidsIn: ['0000000000000000000000000000000000000000000000000000000000000000'],
        npksOut: [1390849295786071768276380950238675083608645509734n],
        nullifiers: ['0x05802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee'],
        nullifyingKey:
          8368299126798249740586535953124199418524409103803955764525436743456763691384n,
        railgunTxidMerkleProofIndices:
          '0000000000000000000000000000000000000000000000000000000000000000',
        railgunTxidMerkleProofPathElements: [
          '0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc',
          '01c405064436affeae1fc8e30b2e417b4243bbb819adca3b55bb32efc3e43a4f',
          '0888d37652d10d1781db54b70af87b42a2916e87118f507218f9a42a58e85ed2',
          '183f531ead7217ebc316b4c02a2aad5ad87a1d56d4fb9ed81bf84f644549eaf5',
          '093c48f1ecedf2baec231f0af848a57a76c6cf05b290a396707972e1defd17df',
          '1437bb465994e0453357c17a676b9fdba554e215795ebc17ea5012770dfb77c7',
          '12359ef9572912b49f44556b8bbbfa69318955352f54cfa35cb0f41309ed445a',
          '2dc656dadc82cf7a4707786f4d682b0f130b6515f7927bde48214d37ec25a46c',
          '2500bdfc1592791583acefd050bc439a87f1d8e8697eb773e8e69b44973e6fdc',
          '244ae3b19397e842778b254cd15c037ed49190141b288ff10eb1390b34dc2c31',
          '0ca2b107491c8ca6e5f7e22403ea8529c1e349a1057b8713e09ca9f5b9294d46',
          '18593c75a9e42af27b5e5b56b99c4c6a5d7e7d6e362f00c8e3f69aeebce52313',
          '17aca915b237b04f873518947a1f440f0c1477a6ac79299b3be46858137d4bfb',
          '2726c22ad3d9e23414887e8233ee83cc51603f58c48a9c9e33cb1f306d4365c0',
          '08c5bd0f85cef2f8c3c1412a2b69ee943c6925ecf79798bb2b84e1b76d26871f',
          '27f7c465045e0a4d8bec7c13e41d793734c50006ca08920732ce8c3096261435',
        ],
        randomsIn: ['67c600e777b86d3a1e72a53092e9fe85'],
        spendingPublicKey: [
          15684838006997671713939066069845237677934334329285343229142447933587909549584n,
          11878614856120328179849762231924033298788609151532558727282528569229552954628n,
        ],
        token: '0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0',
        utxoPositionsIn: [0],
        utxoTreesIn: 0,
        valuesIn: [109725000000000000000000n],
        valuesOut: [109725000000000000000000n],
      },
      ['0x27f34a83697e22f45febe94fd7e66223cd3109736f7cf15a7ab31fdcae73fbcb'],
    );

    // check the transactions log
    const history = await wallet.getTransactionHistory(chain, undefined);
    expect(history.length).to.equal(2);

    const tokenFormatted = formatToByteLength(tokenAddress, ByteLength.UINT_256, false);

    // Make sure nullifier events map to completed txid.
    const nullifiers = transactions.map((transaction) => transaction.nullifiers).flat() as string[];
    const completedTxid = await engine.getCompletedTxidFromNullifiers(
      TXIDVersion.V2_PoseidonMerkle,
      chain,
      nullifiers,
    );
    expect(completedTxid).to.equal(transactTx.hash);

    // Check first output: Shield (receive only).
    expect(history[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109725000000000000000000'),
        memoText: undefined,
        senderAddress: undefined,
        shieldFee: '275000000000000000000',
      },
    ]);
    expect(history[0].transferTokenAmounts).deep.eq([]);
    expect(history[0].relayerFeeTokenAmount).eq(undefined);
    expect(history[0].changeTokenAmounts).deep.eq([]);
    expect(history[0].unshieldTokenAmounts).deep.eq([]);

    // Check second output: Unshield (relayer fee + change).
    // NOTE: No receive token amounts should be logged by history.
    expect(history[1].receiveTokenAmounts).deep.eq(
      [],
      "Receive amount should be filtered out - it's the same as change output.",
    );
    expect(history[1].transferTokenAmounts).deep.eq([]);
    expect(history[1].relayerFeeTokenAmount).eq(undefined);
    expect(history[1].changeTokenAmounts).deep.eq([]); // No change output
    expect(history[1].unshieldTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109450687500000000000000'), // balance minus fee
        recipientAddress: ethersWallet.address,
        memoText: undefined,
        senderAddress: undefined,
        unshieldFee: '274312500000000000000',
      },
    ]);
  }).timeout(120000);

  it('[HH] Should shield, transfer and update balance, and pull formatted spend/receive transaction history', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    const initialBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(initialBalance).to.equal(undefined);

    const address = wallet.getAddress(chain);
    await shieldTestTokens(address, BigInt(110000) * DECIMALS_18);

    const balance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(balance).to.equal(BigInt('109725000000000000000000'));

    // Create transaction
    const transactionBatch = new TransactionBatch(chain);

    const memoText =
      'A really long memo with emojis 😐 👩🏾‍🔧 and other text, in order to test a major memo for a real live production use case.';

    const tokenData = getTokenDataERC20(tokenAddress);

    // Add output for Transfer
    transactionBatch.addOutput(
      TransactNote.createTransfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        10n,
        tokenData,
        wallet.getViewingKeyPair(),
        true, // showSenderAddressToRecipient
        OutputType.Transfer,
        memoText,
      ),
    );

    const relayerMemoText = 'A short memo with only 32 chars.';

    // Add output for mock Relayer
    transactionBatch.addOutput(
      TransactNote.createTransfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        1n,
        tokenData,
        wallet.getViewingKeyPair(),
        false, // showSenderAddressToRecipient
        OutputType.RelayerFee,
        relayerMemoText, // memoText
      ),
    );

    const transactions = await transactionBatch.generateTransactions(
      engine.prover,
      wallet,
      txidVersion,
      testEncryptionKey,
      () => {},
    );
    const transact = await railgunSmartWalletContract.transact(transactions);

    const transactTx = await sendTransactionWithLatestNonce(ethersWallet, transact);
    await transactTx.wait();
    await Promise.all([
      promiseTimeout(awaitMultipleScans(wallet, chain, 2), 15000, 'Timed out wallet1 scan'),
      promiseTimeout(awaitMultipleScans(wallet2, chain, 2), 15000, 'Timed out wallet2 scan'),
    ]);

    // BALANCE = shielded amount - 300(decimals) - 1
    const newBalance = await wallet.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(newBalance).to.equal(109724999999999999999989n, 'Failed to receive expected balance');

    const newBalance2 = await wallet2.getBalanceERC20(txidVersion, chain, tokenAddress);
    expect(newBalance2).to.equal(BigInt(11));

    // check the transactions log
    const history = await wallet.getTransactionHistory(chain, undefined);
    expect(history.length).to.equal(2);

    const tokenFormatted = formatToByteLength(tokenAddress, ByteLength.UINT_256, false);

    // Check first output: Shield (receive only).
    expect(history[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109725000000000000000000'),
        memoText: undefined,
        senderAddress: undefined,
        shieldFee: '275000000000000000000',
      },
    ]);
    expect(history[0].transferTokenAmounts).deep.eq([]);
    expect(history[0].relayerFeeTokenAmount).eq(undefined);
    expect(history[0].changeTokenAmounts).deep.eq([]);
    expect(history[0].unshieldTokenAmounts).deep.eq([]);

    // Check second output: Unshield (relayer fee + change).
    // NOTE: No receive token amounts should be logged by history.
    expect(history[1].receiveTokenAmounts).deep.eq(
      [],
      "Receive amount should be filtered out - it's the same as change output.",
    );
    expect(history[1].transferTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt(10),
        noteAnnotationData: {
          outputType: OutputType.Transfer,
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          senderRandom: history[1].transferTokenAmounts[0].noteAnnotationData!.senderRandom,
          walletSource: 'test wallet',
        },
        recipientAddress: wallet2.getAddress(),
        memoText,
      },
    ]);
    expect(history[1].relayerFeeTokenAmount).deep.eq({
      tokenData: getTokenDataERC20(tokenAddress),
      tokenHash: tokenFormatted,
      amount: BigInt(1),
      noteAnnotationData: {
        outputType: OutputType.RelayerFee,
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        senderRandom: history[1].relayerFeeTokenAmount!.noteAnnotationData!.senderRandom,
        walletSource: 'test wallet',
      },
      memoText: relayerMemoText,
    });
    expect(history[1].changeTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt('109724999999999999999989'),
        noteAnnotationData: {
          outputType: OutputType.Change,
          senderRandom: MEMO_SENDER_RANDOM_NULL,
          walletSource: 'test wallet',
        },
        memoText: undefined,
      },
    ]);
    expect(history[1].unshieldTokenAmounts).deep.eq([]);

    const history2 = await wallet2.getTransactionHistory(chain, undefined);
    expect(history2.length).to.equal(1);
    expect(history2[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt(10),
        memoText,
        senderAddress: wallet.getAddress(),
        shieldFee: undefined,
      },
      {
        tokenData: getTokenDataERC20(tokenAddress),
        tokenHash: tokenFormatted,
        amount: BigInt(1),
        memoText: relayerMemoText,
        senderAddress: undefined,
        shieldFee: undefined,
      },
    ]);
    expect(history2[0].transferTokenAmounts).deep.eq([]);
    expect(history2[0].relayerFeeTokenAmount).eq(undefined);
    expect(history2[0].changeTokenAmounts).deep.eq([]);
    expect(history2[0].unshieldTokenAmounts).deep.eq([]);
  }).timeout(90000);

  it('[HH] Should shield NFTs, transfer & unshield NFTs, and pull formatted spend/receive NFT history', async function run() {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      this.skip();
      return;
    }

    // Mint NFTs
    await mintNFTsID01ForTest(nft, ethersWallet);

    // Approve shields
    const approval = await nft.setApprovalForAll(railgunSmartWalletContract.address, true);
    await approval.wait();

    // Shield first NFT
    await shieldNFTForTest(
      wallet,
      ethersWallet,
      railgunSmartWalletContract,
      chain,
      random,
      nftAddress,
      '1',
    );

    const history = await wallet.getTransactionHistory(chain, undefined);
    expect(history.length).to.equal(1);

    const tokenDataNFT0 = getTokenDataNFT(nftAddress, TokenType.ERC721, BigInt(0).toString());
    const tokenHashNFT0 = getTokenDataHash(tokenDataNFT0);

    const tokenDataNFT1 = getTokenDataNFT(nftAddress, TokenType.ERC721, BigInt(1).toString());
    const tokenHashNFT1 = getTokenDataHash(tokenDataNFT1);

    // Check first output: Shield (receive only).
    expect(history[0].receiveTokenAmounts).deep.eq([
      {
        tokenData: tokenDataNFT1,
        tokenHash: tokenHashNFT1,
        amount: BigInt(1),
        memoText: undefined,
        senderAddress: undefined,
        shieldFee: undefined,
      },
    ]);
    expect(history[0].transferTokenAmounts).deep.eq([]);
    expect(history[0].relayerFeeTokenAmount).eq(undefined);
    expect(history[0].changeTokenAmounts).deep.eq([]);
    expect(history[0].unshieldTokenAmounts).deep.eq([]);

    // Shield another NFT.
    const shield2 = await shieldNFTForTest(
      wallet,
      ethersWallet,
      railgunSmartWalletContract,
      chain,
      random,
      nftAddress,
      '0',
    );

    // Shield tokens for Relayer Fee.
    await shieldTestTokens(wallet.getAddress(), BigInt(110000) * DECIMALS_18);

    // Transfer NFT to another wallet.

    // Create transaction
    const transactionBatch = new TransactionBatch(chain);

    const memoText =
      'A really long memo with emojis 😐 👩🏾‍🔧 and other text, in order to test a major memo for a real live production use case.';

    // Add output for Transfer
    transactionBatch.addOutput(
      TransactNote.createERC721Transfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        tokenDataNFT1,
        wallet.getViewingKeyPair(),
        true, // showSenderAddressToRecipient
        memoText,
      ),
    );

    // Add output for NFT Unshield
    const unshieldNote = new UnshieldNoteNFT(
      ethersWallet.address,
      shield2.tokenData as NFTTokenData,
    );
    transactionBatch.addUnshieldData(unshieldNote.unshieldData);

    const relayerMemoText = 'A short memo with only 32 chars.';

    const tokenDataRelayerFee = getTokenDataERC20(erc20Address);

    // Add output for mock Relayer
    transactionBatch.addOutput(
      TransactNote.createTransfer(
        wallet2.addressKeys,
        wallet.addressKeys,
        20n,
        tokenDataRelayerFee,
        wallet.getViewingKeyPair(),
        false, // showSenderAddressToRecipient
        OutputType.RelayerFee,
        relayerMemoText, // memoText
      ),
    );

    const transactions = await transactionBatch.generateTransactions(
      engine.prover,
      wallet,
      txidVersion,
      testEncryptionKey,
      () => {},
    );
    const transact = await railgunSmartWalletContract.transact(transactions);

    const transactTx = await sendTransactionWithLatestNonce(ethersWallet, transact);
    await transactTx.wait();
    await Promise.all([
      promiseTimeout(awaitMultipleScans(wallet, chain, 4), 15000, 'Timed out wallet1 scan'),
      promiseTimeout(awaitMultipleScans(wallet2, chain, 2), 15000, 'Timed out wallet2 scan'),
    ]);

    const historyAfterTransfer = await wallet.getTransactionHistory(chain, undefined);
    expect(historyAfterTransfer.length).to.equal(4);

    const relayerFeeTokenData = getTokenDataERC20(tokenAddress);
    const relayerFeeTokenHash = getTokenDataHash(relayerFeeTokenData);

    expect(historyAfterTransfer.length).to.equal(4, 'Expected 4 history records');
    expect(historyAfterTransfer[3].transferTokenAmounts.length).to.equal(
      1,
      'Expected at least 1 transfer',
    );

    expect(historyAfterTransfer[3].receiveTokenAmounts).deep.eq([]);
    expect(historyAfterTransfer[3].transferTokenAmounts).deep.eq([
      {
        tokenData: tokenDataNFT1,
        tokenHash: tokenHashNFT1,
        amount: BigInt(1),
        noteAnnotationData: {
          outputType: OutputType.Transfer,
          senderRandom:
            // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
            historyAfterTransfer[3].transferTokenAmounts[0].noteAnnotationData!.senderRandom,
          walletSource: 'test wallet',
        },
        recipientAddress: wallet2.getAddress(),
        memoText,
      },
    ]);
    expect(historyAfterTransfer[3].relayerFeeTokenAmount).deep.eq({
      tokenData: relayerFeeTokenData,
      tokenHash: relayerFeeTokenHash,
      amount: BigInt(20),
      noteAnnotationData: {
        outputType: OutputType.RelayerFee,
        senderRandom:
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          historyAfterTransfer[3].relayerFeeTokenAmount!.noteAnnotationData!.senderRandom,
        walletSource: 'test wallet',
      },
      memoText: relayerMemoText,
    });
    expect(historyAfterTransfer[3].changeTokenAmounts).deep.eq([
      {
        tokenData: relayerFeeTokenData,
        tokenHash: relayerFeeTokenHash,
        amount: BigInt('109724999999999999999980'),
        noteAnnotationData: {
          outputType: OutputType.Change,
          senderRandom: MEMO_SENDER_RANDOM_NULL,
          walletSource: 'test wallet',
        },
        memoText: undefined,
      },
    ]);
    expect(historyAfterTransfer[3].unshieldTokenAmounts).deep.eq([
      {
        tokenData: tokenDataNFT0,
        tokenHash: tokenHashNFT0,
        amount: BigInt(1),
        recipientAddress: ethersWallet.address,
        memoText: undefined,
        senderAddress: undefined,
        unshieldFee: '0',
      },
    ]);
  }).timeout(120000);

  it('Should set/get last synced block', async () => {
    const chainForSyncedBlock = {
      type: ChainType.EVM,
      id: 10010,
    };
    let lastSyncedBlock = await engine.getLastSyncedBlock(chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(undefined);
    await engine.setLastSyncedBlock(chainForSyncedBlock, 100);
    lastSyncedBlock = await engine.getLastSyncedBlock(chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100);
    await engine.setLastSyncedBlock(chainForSyncedBlock, 100000);
    lastSyncedBlock = await engine.getLastSyncedBlock(chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100000);
  });

  it('Should set/get utxo merkletree history version', async () => {
    const chainForSyncedBlock = {
      type: ChainType.EVM,
      id: 10010,
    };
    let lastSyncedBlock = await engine.getLastSyncedBlock(chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(undefined);
    await engine.setUTXOMerkletreeHistoryVersion(chainForSyncedBlock, 100);
    lastSyncedBlock = await engine.getUTXOMerkletreeHistoryVersion(chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100);
    await engine.setUTXOMerkletreeHistoryVersion(chainForSyncedBlock, 100000);
    lastSyncedBlock = await engine.getUTXOMerkletreeHistoryVersion(chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100000);
  });

  it('Should set/get txid merkletree history version', async () => {
    const chainForSyncedBlock = {
      type: ChainType.EVM,
      id: 10010,
    };
    let lastSyncedBlock = await engine.getLastSyncedBlock(chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(undefined);
    await engine.setTxidMerkletreeHistoryVersion(chainForSyncedBlock, 100);
    lastSyncedBlock = await engine.getTxidMerkletreeHistoryVersion(chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100);
    await engine.setTxidMerkletreeHistoryVersion(chainForSyncedBlock, 100000);
    lastSyncedBlock = await engine.getTxidMerkletreeHistoryVersion(chainForSyncedBlock);
    expect(lastSyncedBlock).to.equal(100000);
  });

  afterEach(async () => {
    if (!isDefined(process.env.RUN_HARDHAT_TESTS)) {
      return;
    }

    await provider.send('evm_revert', [snapshot]);

    await txidMerkletree?.clearDataForMerkletree();

    transactNoteRandomStub?.restore();
    transactSenderRandomStub?.restore();
    aesGetRandomIVStub?.restore();

    await engine?.unload();
  });
});
