import { SpendingSolutionGroup, TXO } from '../models/txo-types';
import { minBigInt } from '../utils/bigint';
import { TreeBalance } from '../models/wallet-types';
import { VALID_INPUT_COUNTS, isValidNullifierCount } from './nullifiers';
import { calculateTotalSpend, filterZeroUTXOs, sortUTXOsByAscendingValue } from './utxos';
import { TransactNote } from '../note/transact-note';
import { TokenData } from '../models';
import EngineDebug from '../debugger/debugger';
import { ByteLength, formatToByteLength } from '../utils';

export const CONSOLIDATE_BALANCE_ERROR =
  'This transaction requires a complex circuit for multi-sending, which is not supported by RAILGUN at this time. Select a different Relayer fee token or send tokens to a single address to resolve.';

type SolutionSpendingGroupGenerator = (
  tree: number,
  solutionValue: bigint,
  utxos: TXO[],
) => SpendingSolutionGroup;

const logTreeSortedBalancesMetadata = (treeSortedBalances: TreeBalance[]) => {
  EngineDebug.log('treeSortedBalances metadata:');
  treeSortedBalances.forEach((treeBalance) => {
    EngineDebug.log(`Token: ${treeBalance.tokenData.tokenAddress}`);
    EngineDebug.log(`Total balance: ${treeBalance.balance.toString()}`);
    EngineDebug.log(
      `UTXOs: ${filterZeroUTXOs(treeBalance.utxos)
        .map((utxo) => utxo.note.value.toString())
        .join(', ')}`,
    );
  });
};

/**
 * UTXO with value 0n. All other fields are placeholders.
 * The circuit will ignore fields if value is 0.
 */
const createNullUTXO = (): TXO => {
  const nullTransactNote = TransactNote.createNullNote();
  const nullTxid = formatToByteLength('0x00', ByteLength.UINT_256, true);
  return {
    tree: 0,
    position: 100000, // out of bounds position - so we don't have collisions on nullifiers
    spendtxid: false,
    note: nullTransactNote,
    txid: nullTxid,
  };
};

const getUTXOIDPosition = (utxo: TXO): string => {
  return `${utxo.txid}-${utxo.position}`;
};

const createSpendingSolutionsForValue = (
  treeSortedBalances: TreeBalance[],
  value: bigint,
  excludedUTXOIDPositions: string[],
  spendingSolutionGroupGenerator: SolutionSpendingGroupGenerator,
  updateOutputsCallback?: (amountLeft: bigint) => void,
): SpendingSolutionGroup[] => {
  EngineDebug.log('createSpendingSolutionsForValue');
  EngineDebug.log(`totalRequired: ${value.toString()}`);
  EngineDebug.log(`excludedUTXOIDPositions: ${excludedUTXOIDPositions.join(', ')}`);
  logTreeSortedBalancesMetadata(treeSortedBalances);

  if (value === 0n) {
    if (updateOutputsCallback) {
      updateOutputsCallback(0n);
    }

    // Create a 0-value spending solution group.
    // This is used when simulating a circuit transaction, without requiring an input note.
    // Helpful for initial dummy Relayer Fee with recursive gas estimator.
    const nullUtxo = createNullUTXO();
    const utxos = [nullUtxo];
    const nullSpendingSolutionGroup = spendingSolutionGroupGenerator(nullUtxo.tree, value, utxos);
    return [nullSpendingSolutionGroup];
  }

  let amountLeft = value;

  const spendingSolutionGroups: SpendingSolutionGroup[] = [];

  treeSortedBalances.forEach((treeBalance, tree) => {
    while (amountLeft > 0n) {
      const utxos = findNextSolutionBatch(treeBalance, amountLeft, excludedUTXOIDPositions);
      if (!utxos) {
        // No more solutions in this tree.
        break;
      }

      // Don't allow these UTXOs to be used twice.
      excludedUTXOIDPositions.push(...utxos.map(getUTXOIDPosition));

      // Decrement amount left by total spend in UTXOs.
      const totalSpend = calculateTotalSpend(utxos);

      // Solution Value is the smaller of Solution spend value, or required output value.
      const solutionValue = minBigInt(totalSpend, amountLeft);

      // Generate spending solution group, which will be used to create a Transaction.
      const spendingSolutionGroup = spendingSolutionGroupGenerator(tree, solutionValue, utxos);
      spendingSolutionGroups.push(spendingSolutionGroup);

      amountLeft -= totalSpend;

      // For "outputs" search only, we iteratively search through and update an array of output notes.
      if (updateOutputsCallback) {
        updateOutputsCallback(amountLeft);
      }

      if (amountLeft < 0n) {
        // Break out from the forEach loop, and continue with next output.
        return;
      }
    }
  });

  if (amountLeft > 0n) {
    // Could not find enough solutions.
    throw consolidateBalanceError();
  }

  return spendingSolutionGroups;
};

export const createSpendingSolutionGroupsForOutput = (
  tokenData: TokenData,
  treeSortedBalances: TreeBalance[],
  tokenOutput: TransactNote,
  remainingOutputs: TransactNote[],
  excludedUTXOIDPositions: string[],
): SpendingSolutionGroup[] => {
  const spendingSolutionGroupGenerator: SolutionSpendingGroupGenerator = (
    tree: number,
    solutionValue: bigint,
    utxos: TXO[],
  ): SpendingSolutionGroup => {
    const solutionOutput = tokenOutput.newProcessingNoteWithValue(solutionValue);

    return {
      spendingTree: tree,
      utxos,
      tokenOutputs: [solutionOutput],
      unshieldValue: 0n,
      tokenData,
    };
  };

  const updateOutputsCallback = (amountLeft: bigint) => {
    // Remove the "used" output note.
    remainingOutputs.splice(0, 1);

    if (amountLeft > 0n) {
      // Add another remaining output note for any Amount Left.
      remainingOutputs.unshift(tokenOutput.newProcessingNoteWithValue(amountLeft));
    }
  };

  return createSpendingSolutionsForValue(
    treeSortedBalances,
    tokenOutput.value,
    excludedUTXOIDPositions,
    spendingSolutionGroupGenerator,
    updateOutputsCallback,
  );
};

export const createSpendingSolutionGroupsForUnshield = (
  tokenData: TokenData,
  treeSortedBalances: TreeBalance[],
  unshieldValue: bigint,
  excludedUTXOIDPositions: string[],
): SpendingSolutionGroup[] => {
  const spendingSolutionGroupGenerator: SolutionSpendingGroupGenerator = (
    tree: number,
    solutionValue: bigint,
    utxos: TXO[],
  ): SpendingSolutionGroup => {
    return {
      spendingTree: tree,
      utxos,
      tokenOutputs: [],
      unshieldValue: solutionValue,
      tokenData,
    };
  };

  return createSpendingSolutionsForValue(
    treeSortedBalances,
    unshieldValue,
    excludedUTXOIDPositions,
    spendingSolutionGroupGenerator,
  );
};

/**
 * Wallet has appropriate balance in aggregate, but no solutions remain.
 * This means these UTXOs were already excluded, which can only occur in multi-send situations with multiple destination addresses.
 *
 * Example: Out of a 600 balance (550 and 50), sending 100 each to 6 people becomes difficult, because of the constraints on the number of circuit outputs.
 * This would require a 1x6 for the 550 note, and a 1x1 for the 50 note. We do not support a 1x6 circuit.
 * TODO: A possible fix is to update the logic the 1x6 output sends as a 1x10 with 4 null (value 0) outputs.
 * This would be the way to support large multi-receiver transactions.
 */
export const consolidateBalanceError = (): Error => {
  throw new Error(CONSOLIDATE_BALANCE_ERROR);
};

/**
 * Finds next valid nullifier count above the current nullifier count.
 */
export const nextNullifierTarget = (utxoCount: number): Optional<number> =>
  VALID_INPUT_COUNTS.find((n) => n > utxoCount);

export const shouldAddMoreUTXOsForSolutionBatch = (
  currentNullifierCount: number,
  totalNullifierCount: number,
  currentSpend: bigint,
  totalRequired: bigint,
) => {
  if (currentSpend >= totalRequired) {
    // We've hit the target required.
    return false;
  }

  const nullifierTarget = nextNullifierTarget(currentNullifierCount);
  if (!nullifierTarget) {
    // No next nullifier target.
    return false;
  }

  if (nullifierTarget > totalNullifierCount) {
    // Next target is not reachable. Don't add any more UTXOs.
    return false;
  }

  // Total spend < total required, and next nullifier target is reachable.
  // Continue adding nullifiers.
  return true;
};

/**
 * 1. Filter out UTXOs with value 0.
 * 2. Use exact match UTXO for totalRequired value if it exists.
 * 3. Sort by smallest UTXO ascending.
 * 4. Add UTXOs to the batch until we hit the totalRequired value, or exceed the UTXO input count maximum.
 */
export function findNextSolutionBatch(
  treeBalance: TreeBalance,
  totalRequired: bigint,
  excludedUTXOIDPositions: string[],
): Optional<TXO[]> {
  const removedZeroUTXOs = filterZeroUTXOs(treeBalance.utxos);
  const filteredUTXOs = removedZeroUTXOs.filter(
    (utxo) => !excludedUTXOIDPositions.includes(getUTXOIDPosition(utxo)),
  );
  if (!filteredUTXOs.length) {
    // No more solutions in this tree.
    return undefined;
  }

  // Use exact match if it exists.
  const exactMatch = filteredUTXOs.find((utxo) => utxo.note.value === totalRequired);
  if (exactMatch) {
    return [exactMatch];
  }

  // Sort UTXOs by smallest size
  sortUTXOsByAscendingValue(filteredUTXOs);

  // Accumulate UTXOs until we hit the target value
  const utxos: TXO[] = [];

  // Check if sum of UTXOs selected is greater than target
  while (
    shouldAddMoreUTXOsForSolutionBatch(
      utxos.length,
      filteredUTXOs.length,
      calculateTotalSpend(utxos),
      totalRequired,
    )
  ) {
    utxos.push(filteredUTXOs[utxos.length]);
  }

  if (!isValidNullifierCount(utxos.length)) {
    return undefined;
  }

  return utxos;
}
