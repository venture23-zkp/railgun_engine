import { UnshieldStoredEvent } from './event-types';
import { NoteAnnotationData, TokenData } from './formatted-types';
import { TXO } from './txo-types';

export type WalletDetails = {
  treeScannedHeights: number[];
  creationTree: Optional<number>;
  creationTreeHeight: Optional<number>;
};

export type TreeBalance = {
  balance: bigint;
  tokenData: TokenData;
  utxos: TXO[];
};

export type Balances = {
  [tokenHash: string]: TreeBalance;
};

export type BalancesByTree = {
  [tree: string]: TreeBalance[];
};

export type AddressKeys = {
  masterPublicKey: bigint;
  viewingPublicKey: Uint8Array;
};

export type WalletData = {
  mnemonic: string;
  index: number;
  creationBlockNumbers: Optional<number[][]>;
};

export type ViewOnlyWalletData = {
  shareableViewingKey: string;
  creationBlockNumbers: Optional<number[][]>;
};

export type ShareableViewingKeyData = {
  vpriv: string; // viewingPrivateKey
  spub: string; // spendingPublicKey
};

export type TransactionHistoryTokenAmount = {
  tokenHash: string;
  tokenData: TokenData;
  amount: bigint;
  noteAnnotationData?: NoteAnnotationData;
  memoText: Optional<string>;
};
export type TransactionHistoryTransferTokenAmount = TransactionHistoryTokenAmount & {
  recipientAddress: string;
};
export type TransactionHistoryReceiveTokenAmount = TransactionHistoryTokenAmount & {
  senderAddress: Optional<string>;
};
export type TransactionHistoryEntryReceived = {
  txid: string;
  receiveTokenAmounts: TransactionHistoryReceiveTokenAmount[];
};
export type TransactionHistoryEntrySpent = {
  txid: string;
  transferTokenAmounts: TransactionHistoryTransferTokenAmount[];
  changeTokenAmounts: TransactionHistoryTokenAmount[];
  relayerFeeTokenAmount?: TransactionHistoryTokenAmount;
  unshieldTokenAmounts: TransactionHistoryTransferTokenAmount[];
  version: number;
};
export type TransactionHistoryEntry = TransactionHistoryEntrySpent &
  TransactionHistoryEntryReceived;
export type TransactionHistoryEntryPreprocessSpent = {
  txid: string;
  tokenAmounts: TransactionHistoryTokenAmount[];
  version: number;
  unshieldEvents: UnshieldStoredEvent[];
};
export enum TransactionHistoryItemVersion {
  Unknown = 0, // Receive note only: noteAnnotationData metadata not possible
  Legacy = 1, // No noteAnnotationData on spent notes
  UpdatedAug2022 = 2, // Adds noteAnnotationData for spent notes (outputType)
  UpdatedNov2022 = 3, // Adds unshields and possible sender for received notes
}

export enum NoteType {
  Receiver = 'Receiver',
  Spender = 'Spender',
}
