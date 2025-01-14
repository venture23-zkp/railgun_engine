/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumber,
  BigNumberish,
  BytesLike,
  CallOverrides,
  ContractTransaction,
  Overrides,
  PopulatedTransaction,
  Signer,
  utils,
} from "ethers";
import type {
  FunctionFragment,
  Result,
  EventFragment,
} from "@ethersproject/abi";
import type { Listener, Provider } from "@ethersproject/providers";
import type {
  TypedEventFilter,
  TypedEvent,
  TypedListener,
  OnEvent,
  PromiseOrValue,
} from "../../../common";

export declare namespace Staking {
  export type AccountSnapshotStruct = {
    interval: PromiseOrValue<BigNumberish>;
    votingPower: PromiseOrValue<BigNumberish>;
  };

  export type AccountSnapshotStructOutput = [BigNumber, BigNumber] & {
    interval: BigNumber;
    votingPower: BigNumber;
  };

  export type GlobalsSnapshotStruct = {
    interval: PromiseOrValue<BigNumberish>;
    totalVotingPower: PromiseOrValue<BigNumberish>;
    totalStaked: PromiseOrValue<BigNumberish>;
  };

  export type GlobalsSnapshotStructOutput = [
    BigNumber,
    BigNumber,
    BigNumber
  ] & {
    interval: BigNumber;
    totalVotingPower: BigNumber;
    totalStaked: BigNumber;
  };
}

export interface StakingStubInterface extends utils.Interface {
  functions: {
    "DEPLOY_TIME()": FunctionFragment;
    "SNAPSHOT_INTERVAL()": FunctionFragment;
    "STAKE_LOCKTIME()": FunctionFragment;
    "accountSnapshot(address,uint256)": FunctionFragment;
    "accountSnapshotAt(address,uint256,uint256)": FunctionFragment;
    "accountSnapshotLength(address)": FunctionFragment;
    "claim(uint256)": FunctionFragment;
    "currentInterval()": FunctionFragment;
    "delegate(uint256,address)": FunctionFragment;
    "globalsSnapshot(uint256)": FunctionFragment;
    "globalsSnapshotAt(uint256,uint256)": FunctionFragment;
    "globalsSnapshotLength()": FunctionFragment;
    "intervalAtTime(uint256)": FunctionFragment;
    "latestAccountSnapshotInterval(address)": FunctionFragment;
    "latestGlobalsSnapshotInterval()": FunctionFragment;
    "snapshotStub(address)": FunctionFragment;
    "stake(uint256)": FunctionFragment;
    "stakes(address,uint256)": FunctionFragment;
    "stakesLength(address)": FunctionFragment;
    "stakingToken()": FunctionFragment;
    "totalStaked()": FunctionFragment;
    "totalVotingPower()": FunctionFragment;
    "undelegate(uint256)": FunctionFragment;
    "unlock(uint256)": FunctionFragment;
    "votingPower(address)": FunctionFragment;
  };

  getFunction(
    nameOrSignatureOrTopic:
      | "DEPLOY_TIME"
      | "SNAPSHOT_INTERVAL"
      | "STAKE_LOCKTIME"
      | "accountSnapshot"
      | "accountSnapshotAt"
      | "accountSnapshotLength"
      | "claim"
      | "currentInterval"
      | "delegate"
      | "globalsSnapshot"
      | "globalsSnapshotAt"
      | "globalsSnapshotLength"
      | "intervalAtTime"
      | "latestAccountSnapshotInterval"
      | "latestGlobalsSnapshotInterval"
      | "snapshotStub"
      | "stake"
      | "stakes"
      | "stakesLength"
      | "stakingToken"
      | "totalStaked"
      | "totalVotingPower"
      | "undelegate"
      | "unlock"
      | "votingPower"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "DEPLOY_TIME",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "SNAPSHOT_INTERVAL",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "STAKE_LOCKTIME",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "accountSnapshot",
    values: [PromiseOrValue<string>, PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "accountSnapshotAt",
    values: [
      PromiseOrValue<string>,
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<BigNumberish>
    ]
  ): string;
  encodeFunctionData(
    functionFragment: "accountSnapshotLength",
    values: [PromiseOrValue<string>]
  ): string;
  encodeFunctionData(
    functionFragment: "claim",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "currentInterval",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "delegate",
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<string>]
  ): string;
  encodeFunctionData(
    functionFragment: "globalsSnapshot",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "globalsSnapshotAt",
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "globalsSnapshotLength",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "intervalAtTime",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "latestAccountSnapshotInterval",
    values: [PromiseOrValue<string>]
  ): string;
  encodeFunctionData(
    functionFragment: "latestGlobalsSnapshotInterval",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "snapshotStub",
    values: [PromiseOrValue<string>]
  ): string;
  encodeFunctionData(
    functionFragment: "stake",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "stakes",
    values: [PromiseOrValue<string>, PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "stakesLength",
    values: [PromiseOrValue<string>]
  ): string;
  encodeFunctionData(
    functionFragment: "stakingToken",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "totalStaked",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "totalVotingPower",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "undelegate",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "unlock",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "votingPower",
    values: [PromiseOrValue<string>]
  ): string;

  decodeFunctionResult(
    functionFragment: "DEPLOY_TIME",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "SNAPSHOT_INTERVAL",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "STAKE_LOCKTIME",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "accountSnapshot",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "accountSnapshotAt",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "accountSnapshotLength",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "claim", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "currentInterval",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "delegate", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "globalsSnapshot",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "globalsSnapshotAt",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "globalsSnapshotLength",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "intervalAtTime",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "latestAccountSnapshotInterval",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "latestGlobalsSnapshotInterval",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "snapshotStub",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "stake", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "stakes", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "stakesLength",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "stakingToken",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "totalStaked",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "totalVotingPower",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "undelegate", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "unlock", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "votingPower",
    data: BytesLike
  ): Result;

  events: {
    "Claim(address,uint256)": EventFragment;
    "Delegate(address,address,address,uint256,uint256)": EventFragment;
    "Stake(address,uint256,uint256)": EventFragment;
    "Unlock(address,uint256)": EventFragment;
  };

  getEvent(nameOrSignatureOrTopic: "Claim"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "Delegate"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "Stake"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "Unlock"): EventFragment;
}

export interface ClaimEventObject {
  account: string;
  stakeID: BigNumber;
}
export type ClaimEvent = TypedEvent<[string, BigNumber], ClaimEventObject>;

export type ClaimEventFilter = TypedEventFilter<ClaimEvent>;

export interface DelegateEventObject {
  owner: string;
  _from: string;
  to: string;
  stakeID: BigNumber;
  amount: BigNumber;
}
export type DelegateEvent = TypedEvent<
  [string, string, string, BigNumber, BigNumber],
  DelegateEventObject
>;

export type DelegateEventFilter = TypedEventFilter<DelegateEvent>;

export interface StakeEventObject {
  account: string;
  stakeID: BigNumber;
  amount: BigNumber;
}
export type StakeEvent = TypedEvent<
  [string, BigNumber, BigNumber],
  StakeEventObject
>;

export type StakeEventFilter = TypedEventFilter<StakeEvent>;

export interface UnlockEventObject {
  account: string;
  stakeID: BigNumber;
}
export type UnlockEvent = TypedEvent<[string, BigNumber], UnlockEventObject>;

export type UnlockEventFilter = TypedEventFilter<UnlockEvent>;

export interface StakingStub extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  interface: StakingStubInterface;

  queryFilter<TEvent extends TypedEvent>(
    event: TypedEventFilter<TEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined
  ): Promise<Array<TEvent>>;

  listeners<TEvent extends TypedEvent>(
    eventFilter?: TypedEventFilter<TEvent>
  ): Array<TypedListener<TEvent>>;
  listeners(eventName?: string): Array<Listener>;
  removeAllListeners<TEvent extends TypedEvent>(
    eventFilter: TypedEventFilter<TEvent>
  ): this;
  removeAllListeners(eventName?: string): this;
  off: OnEvent<this>;
  on: OnEvent<this>;
  once: OnEvent<this>;
  removeListener: OnEvent<this>;

  functions: {
    DEPLOY_TIME(overrides?: CallOverrides): Promise<[BigNumber]>;

    SNAPSHOT_INTERVAL(overrides?: CallOverrides): Promise<[BigNumber]>;

    STAKE_LOCKTIME(overrides?: CallOverrides): Promise<[BigNumber]>;

    accountSnapshot(
      _account: PromiseOrValue<string>,
      _index: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<[Staking.AccountSnapshotStructOutput]>;

    accountSnapshotAt(
      _account: PromiseOrValue<string>,
      _interval: PromiseOrValue<BigNumberish>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<[Staking.AccountSnapshotStructOutput]>;

    accountSnapshotLength(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    claim(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    currentInterval(overrides?: CallOverrides): Promise<[BigNumber]>;

    delegate(
      _stakeID: PromiseOrValue<BigNumberish>,
      _to: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    globalsSnapshot(
      _index: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<[Staking.GlobalsSnapshotStructOutput]>;

    globalsSnapshotAt(
      _interval: PromiseOrValue<BigNumberish>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<[Staking.GlobalsSnapshotStructOutput]>;

    globalsSnapshotLength(overrides?: CallOverrides): Promise<[BigNumber]>;

    intervalAtTime(
      _time: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    latestAccountSnapshotInterval(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    latestGlobalsSnapshotInterval(
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    snapshotStub(
      _account: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    stake(
      _amount: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    stakes(
      arg0: PromiseOrValue<string>,
      arg1: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<
      [string, BigNumber, BigNumber, BigNumber, BigNumber] & {
        delegate: string;
        amount: BigNumber;
        staketime: BigNumber;
        locktime: BigNumber;
        claimedTime: BigNumber;
      }
    >;

    stakesLength(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    stakingToken(overrides?: CallOverrides): Promise<[string]>;

    totalStaked(overrides?: CallOverrides): Promise<[BigNumber]>;

    totalVotingPower(overrides?: CallOverrides): Promise<[BigNumber]>;

    undelegate(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    unlock(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    votingPower(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;
  };

  DEPLOY_TIME(overrides?: CallOverrides): Promise<BigNumber>;

  SNAPSHOT_INTERVAL(overrides?: CallOverrides): Promise<BigNumber>;

  STAKE_LOCKTIME(overrides?: CallOverrides): Promise<BigNumber>;

  accountSnapshot(
    _account: PromiseOrValue<string>,
    _index: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides
  ): Promise<Staking.AccountSnapshotStructOutput>;

  accountSnapshotAt(
    _account: PromiseOrValue<string>,
    _interval: PromiseOrValue<BigNumberish>,
    _hint: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides
  ): Promise<Staking.AccountSnapshotStructOutput>;

  accountSnapshotLength(
    _account: PromiseOrValue<string>,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  claim(
    _stakeID: PromiseOrValue<BigNumberish>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  currentInterval(overrides?: CallOverrides): Promise<BigNumber>;

  delegate(
    _stakeID: PromiseOrValue<BigNumberish>,
    _to: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  globalsSnapshot(
    _index: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides
  ): Promise<Staking.GlobalsSnapshotStructOutput>;

  globalsSnapshotAt(
    _interval: PromiseOrValue<BigNumberish>,
    _hint: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides
  ): Promise<Staking.GlobalsSnapshotStructOutput>;

  globalsSnapshotLength(overrides?: CallOverrides): Promise<BigNumber>;

  intervalAtTime(
    _time: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  latestAccountSnapshotInterval(
    _account: PromiseOrValue<string>,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  latestGlobalsSnapshotInterval(overrides?: CallOverrides): Promise<BigNumber>;

  snapshotStub(
    _account: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  stake(
    _amount: PromiseOrValue<BigNumberish>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  stakes(
    arg0: PromiseOrValue<string>,
    arg1: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides
  ): Promise<
    [string, BigNumber, BigNumber, BigNumber, BigNumber] & {
      delegate: string;
      amount: BigNumber;
      staketime: BigNumber;
      locktime: BigNumber;
      claimedTime: BigNumber;
    }
  >;

  stakesLength(
    _account: PromiseOrValue<string>,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  stakingToken(overrides?: CallOverrides): Promise<string>;

  totalStaked(overrides?: CallOverrides): Promise<BigNumber>;

  totalVotingPower(overrides?: CallOverrides): Promise<BigNumber>;

  undelegate(
    _stakeID: PromiseOrValue<BigNumberish>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  unlock(
    _stakeID: PromiseOrValue<BigNumberish>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  votingPower(
    arg0: PromiseOrValue<string>,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  callStatic: {
    DEPLOY_TIME(overrides?: CallOverrides): Promise<BigNumber>;

    SNAPSHOT_INTERVAL(overrides?: CallOverrides): Promise<BigNumber>;

    STAKE_LOCKTIME(overrides?: CallOverrides): Promise<BigNumber>;

    accountSnapshot(
      _account: PromiseOrValue<string>,
      _index: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<Staking.AccountSnapshotStructOutput>;

    accountSnapshotAt(
      _account: PromiseOrValue<string>,
      _interval: PromiseOrValue<BigNumberish>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<Staking.AccountSnapshotStructOutput>;

    accountSnapshotLength(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    claim(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<void>;

    currentInterval(overrides?: CallOverrides): Promise<BigNumber>;

    delegate(
      _stakeID: PromiseOrValue<BigNumberish>,
      _to: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<void>;

    globalsSnapshot(
      _index: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<Staking.GlobalsSnapshotStructOutput>;

    globalsSnapshotAt(
      _interval: PromiseOrValue<BigNumberish>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<Staking.GlobalsSnapshotStructOutput>;

    globalsSnapshotLength(overrides?: CallOverrides): Promise<BigNumber>;

    intervalAtTime(
      _time: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    latestAccountSnapshotInterval(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    latestGlobalsSnapshotInterval(
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    snapshotStub(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<void>;

    stake(
      _amount: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    stakes(
      arg0: PromiseOrValue<string>,
      arg1: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<
      [string, BigNumber, BigNumber, BigNumber, BigNumber] & {
        delegate: string;
        amount: BigNumber;
        staketime: BigNumber;
        locktime: BigNumber;
        claimedTime: BigNumber;
      }
    >;

    stakesLength(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    stakingToken(overrides?: CallOverrides): Promise<string>;

    totalStaked(overrides?: CallOverrides): Promise<BigNumber>;

    totalVotingPower(overrides?: CallOverrides): Promise<BigNumber>;

    undelegate(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<void>;

    unlock(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<void>;

    votingPower(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;
  };

  filters: {
    "Claim(address,uint256)"(
      account?: PromiseOrValue<string> | null,
      stakeID?: PromiseOrValue<BigNumberish> | null
    ): ClaimEventFilter;
    Claim(
      account?: PromiseOrValue<string> | null,
      stakeID?: PromiseOrValue<BigNumberish> | null
    ): ClaimEventFilter;

    "Delegate(address,address,address,uint256,uint256)"(
      owner?: PromiseOrValue<string> | null,
      _from?: PromiseOrValue<string> | null,
      to?: PromiseOrValue<string> | null,
      stakeID?: null,
      amount?: null
    ): DelegateEventFilter;
    Delegate(
      owner?: PromiseOrValue<string> | null,
      _from?: PromiseOrValue<string> | null,
      to?: PromiseOrValue<string> | null,
      stakeID?: null,
      amount?: null
    ): DelegateEventFilter;

    "Stake(address,uint256,uint256)"(
      account?: PromiseOrValue<string> | null,
      stakeID?: PromiseOrValue<BigNumberish> | null,
      amount?: null
    ): StakeEventFilter;
    Stake(
      account?: PromiseOrValue<string> | null,
      stakeID?: PromiseOrValue<BigNumberish> | null,
      amount?: null
    ): StakeEventFilter;

    "Unlock(address,uint256)"(
      account?: PromiseOrValue<string> | null,
      stakeID?: PromiseOrValue<BigNumberish> | null
    ): UnlockEventFilter;
    Unlock(
      account?: PromiseOrValue<string> | null,
      stakeID?: PromiseOrValue<BigNumberish> | null
    ): UnlockEventFilter;
  };

  estimateGas: {
    DEPLOY_TIME(overrides?: CallOverrides): Promise<BigNumber>;

    SNAPSHOT_INTERVAL(overrides?: CallOverrides): Promise<BigNumber>;

    STAKE_LOCKTIME(overrides?: CallOverrides): Promise<BigNumber>;

    accountSnapshot(
      _account: PromiseOrValue<string>,
      _index: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    accountSnapshotAt(
      _account: PromiseOrValue<string>,
      _interval: PromiseOrValue<BigNumberish>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    accountSnapshotLength(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    claim(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    currentInterval(overrides?: CallOverrides): Promise<BigNumber>;

    delegate(
      _stakeID: PromiseOrValue<BigNumberish>,
      _to: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    globalsSnapshot(
      _index: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    globalsSnapshotAt(
      _interval: PromiseOrValue<BigNumberish>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    globalsSnapshotLength(overrides?: CallOverrides): Promise<BigNumber>;

    intervalAtTime(
      _time: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    latestAccountSnapshotInterval(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    latestGlobalsSnapshotInterval(
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    snapshotStub(
      _account: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    stake(
      _amount: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    stakes(
      arg0: PromiseOrValue<string>,
      arg1: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    stakesLength(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    stakingToken(overrides?: CallOverrides): Promise<BigNumber>;

    totalStaked(overrides?: CallOverrides): Promise<BigNumber>;

    totalVotingPower(overrides?: CallOverrides): Promise<BigNumber>;

    undelegate(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    unlock(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    votingPower(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;
  };

  populateTransaction: {
    DEPLOY_TIME(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    SNAPSHOT_INTERVAL(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    STAKE_LOCKTIME(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    accountSnapshot(
      _account: PromiseOrValue<string>,
      _index: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    accountSnapshotAt(
      _account: PromiseOrValue<string>,
      _interval: PromiseOrValue<BigNumberish>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    accountSnapshotLength(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    claim(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    currentInterval(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    delegate(
      _stakeID: PromiseOrValue<BigNumberish>,
      _to: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    globalsSnapshot(
      _index: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    globalsSnapshotAt(
      _interval: PromiseOrValue<BigNumberish>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    globalsSnapshotLength(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    intervalAtTime(
      _time: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    latestAccountSnapshotInterval(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    latestGlobalsSnapshotInterval(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    snapshotStub(
      _account: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    stake(
      _amount: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    stakes(
      arg0: PromiseOrValue<string>,
      arg1: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    stakesLength(
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    stakingToken(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    totalStaked(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    totalVotingPower(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    undelegate(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    unlock(
      _stakeID: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    votingPower(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;
  };
}
