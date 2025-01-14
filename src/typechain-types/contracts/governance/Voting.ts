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
} from "../../common";

export declare namespace Voting {
  export type CallStruct = {
    callContract: PromiseOrValue<string>;
    data: PromiseOrValue<BytesLike>;
    value: PromiseOrValue<BigNumberish>;
  };

  export type CallStructOutput = [string, string, BigNumber] & {
    callContract: string;
    data: string;
    value: BigNumber;
  };
}

export interface VotingInterface extends utils.Interface {
  functions: {
    "DELEGATOR_CONTRACT()": FunctionFragment;
    "EXECUTION_END_OFFSET()": FunctionFragment;
    "EXECUTION_START_OFFSET()": FunctionFragment;
    "PROPOSAL_SPONSOR_THRESHOLD()": FunctionFragment;
    "QUORUM()": FunctionFragment;
    "SPONSOR_LOCKOUT_TIME()": FunctionFragment;
    "SPONSOR_WINDOW()": FunctionFragment;
    "STAKING_CONTRACT()": FunctionFragment;
    "VOTING_NAY_END_OFFSET()": FunctionFragment;
    "VOTING_START_OFFSET()": FunctionFragment;
    "VOTING_YAY_END_OFFSET()": FunctionFragment;
    "callVote(uint256)": FunctionFragment;
    "createProposal(string,(address,bytes,uint256)[])": FunctionFragment;
    "executeProposal(uint256)": FunctionFragment;
    "getActions(uint256)": FunctionFragment;
    "getSponsored(uint256,address)": FunctionFragment;
    "getVotes(uint256,address)": FunctionFragment;
    "lastSponsored(address)": FunctionFragment;
    "proposals(uint256)": FunctionFragment;
    "proposalsLength()": FunctionFragment;
    "setVotingKey(address)": FunctionFragment;
    "sponsorProposal(uint256,uint256,address,uint256)": FunctionFragment;
    "unsponsorProposal(uint256,uint256,address)": FunctionFragment;
    "vote(uint256,uint256,bool,address,uint256)": FunctionFragment;
    "votingKey(address)": FunctionFragment;
  };

  getFunction(
    nameOrSignatureOrTopic:
      | "DELEGATOR_CONTRACT"
      | "EXECUTION_END_OFFSET"
      | "EXECUTION_START_OFFSET"
      | "PROPOSAL_SPONSOR_THRESHOLD"
      | "QUORUM"
      | "SPONSOR_LOCKOUT_TIME"
      | "SPONSOR_WINDOW"
      | "STAKING_CONTRACT"
      | "VOTING_NAY_END_OFFSET"
      | "VOTING_START_OFFSET"
      | "VOTING_YAY_END_OFFSET"
      | "callVote"
      | "createProposal"
      | "executeProposal"
      | "getActions"
      | "getSponsored"
      | "getVotes"
      | "lastSponsored"
      | "proposals"
      | "proposalsLength"
      | "setVotingKey"
      | "sponsorProposal"
      | "unsponsorProposal"
      | "vote"
      | "votingKey"
  ): FunctionFragment;

  encodeFunctionData(
    functionFragment: "DELEGATOR_CONTRACT",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "EXECUTION_END_OFFSET",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "EXECUTION_START_OFFSET",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "PROPOSAL_SPONSOR_THRESHOLD",
    values?: undefined
  ): string;
  encodeFunctionData(functionFragment: "QUORUM", values?: undefined): string;
  encodeFunctionData(
    functionFragment: "SPONSOR_LOCKOUT_TIME",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "SPONSOR_WINDOW",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "STAKING_CONTRACT",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "VOTING_NAY_END_OFFSET",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "VOTING_START_OFFSET",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "VOTING_YAY_END_OFFSET",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "callVote",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "createProposal",
    values: [PromiseOrValue<string>, Voting.CallStruct[]]
  ): string;
  encodeFunctionData(
    functionFragment: "executeProposal",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "getActions",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "getSponsored",
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<string>]
  ): string;
  encodeFunctionData(
    functionFragment: "getVotes",
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<string>]
  ): string;
  encodeFunctionData(
    functionFragment: "lastSponsored",
    values: [PromiseOrValue<string>]
  ): string;
  encodeFunctionData(
    functionFragment: "proposals",
    values: [PromiseOrValue<BigNumberish>]
  ): string;
  encodeFunctionData(
    functionFragment: "proposalsLength",
    values?: undefined
  ): string;
  encodeFunctionData(
    functionFragment: "setVotingKey",
    values: [PromiseOrValue<string>]
  ): string;
  encodeFunctionData(
    functionFragment: "sponsorProposal",
    values: [
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<string>,
      PromiseOrValue<BigNumberish>
    ]
  ): string;
  encodeFunctionData(
    functionFragment: "unsponsorProposal",
    values: [
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<string>
    ]
  ): string;
  encodeFunctionData(
    functionFragment: "vote",
    values: [
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<boolean>,
      PromiseOrValue<string>,
      PromiseOrValue<BigNumberish>
    ]
  ): string;
  encodeFunctionData(
    functionFragment: "votingKey",
    values: [PromiseOrValue<string>]
  ): string;

  decodeFunctionResult(
    functionFragment: "DELEGATOR_CONTRACT",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "EXECUTION_END_OFFSET",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "EXECUTION_START_OFFSET",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "PROPOSAL_SPONSOR_THRESHOLD",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "QUORUM", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "SPONSOR_LOCKOUT_TIME",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "SPONSOR_WINDOW",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "STAKING_CONTRACT",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "VOTING_NAY_END_OFFSET",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "VOTING_START_OFFSET",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "VOTING_YAY_END_OFFSET",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "callVote", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "createProposal",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "executeProposal",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "getActions", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "getSponsored",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "getVotes", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "lastSponsored",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "proposals", data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: "proposalsLength",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "setVotingKey",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "sponsorProposal",
    data: BytesLike
  ): Result;
  decodeFunctionResult(
    functionFragment: "unsponsorProposal",
    data: BytesLike
  ): Result;
  decodeFunctionResult(functionFragment: "vote", data: BytesLike): Result;
  decodeFunctionResult(functionFragment: "votingKey", data: BytesLike): Result;

  events: {
    "Execution(uint256)": EventFragment;
    "Proposal(uint256,address)": EventFragment;
    "Sponsorship(uint256,address,uint256)": EventFragment;
    "SponsorshipRevocation(uint256,address,uint256)": EventFragment;
    "VoteCall(uint256)": EventFragment;
    "VoteCast(uint256,address,bool,uint256)": EventFragment;
    "VoteKeySet(address,address)": EventFragment;
  };

  getEvent(nameOrSignatureOrTopic: "Execution"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "Proposal"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "Sponsorship"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "SponsorshipRevocation"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "VoteCall"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "VoteCast"): EventFragment;
  getEvent(nameOrSignatureOrTopic: "VoteKeySet"): EventFragment;
}

export interface ExecutionEventObject {
  id: BigNumber;
}
export type ExecutionEvent = TypedEvent<[BigNumber], ExecutionEventObject>;

export type ExecutionEventFilter = TypedEventFilter<ExecutionEvent>;

export interface ProposalEventObject {
  id: BigNumber;
  proposer: string;
}
export type ProposalEvent = TypedEvent<
  [BigNumber, string],
  ProposalEventObject
>;

export type ProposalEventFilter = TypedEventFilter<ProposalEvent>;

export interface SponsorshipEventObject {
  id: BigNumber;
  sponsor: string;
  amount: BigNumber;
}
export type SponsorshipEvent = TypedEvent<
  [BigNumber, string, BigNumber],
  SponsorshipEventObject
>;

export type SponsorshipEventFilter = TypedEventFilter<SponsorshipEvent>;

export interface SponsorshipRevocationEventObject {
  id: BigNumber;
  sponsor: string;
  amount: BigNumber;
}
export type SponsorshipRevocationEvent = TypedEvent<
  [BigNumber, string, BigNumber],
  SponsorshipRevocationEventObject
>;

export type SponsorshipRevocationEventFilter =
  TypedEventFilter<SponsorshipRevocationEvent>;

export interface VoteCallEventObject {
  id: BigNumber;
}
export type VoteCallEvent = TypedEvent<[BigNumber], VoteCallEventObject>;

export type VoteCallEventFilter = TypedEventFilter<VoteCallEvent>;

export interface VoteCastEventObject {
  id: BigNumber;
  voter: string;
  affirmative: boolean;
  votes: BigNumber;
}
export type VoteCastEvent = TypedEvent<
  [BigNumber, string, boolean, BigNumber],
  VoteCastEventObject
>;

export type VoteCastEventFilter = TypedEventFilter<VoteCastEvent>;

export interface VoteKeySetEventObject {
  account: string;
  votingKey: string;
}
export type VoteKeySetEvent = TypedEvent<
  [string, string],
  VoteKeySetEventObject
>;

export type VoteKeySetEventFilter = TypedEventFilter<VoteKeySetEvent>;

export interface Voting extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  interface: VotingInterface;

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
    DELEGATOR_CONTRACT(overrides?: CallOverrides): Promise<[string]>;

    EXECUTION_END_OFFSET(overrides?: CallOverrides): Promise<[BigNumber]>;

    EXECUTION_START_OFFSET(overrides?: CallOverrides): Promise<[BigNumber]>;

    PROPOSAL_SPONSOR_THRESHOLD(overrides?: CallOverrides): Promise<[BigNumber]>;

    QUORUM(overrides?: CallOverrides): Promise<[BigNumber]>;

    SPONSOR_LOCKOUT_TIME(overrides?: CallOverrides): Promise<[BigNumber]>;

    SPONSOR_WINDOW(overrides?: CallOverrides): Promise<[BigNumber]>;

    STAKING_CONTRACT(overrides?: CallOverrides): Promise<[string]>;

    VOTING_NAY_END_OFFSET(overrides?: CallOverrides): Promise<[BigNumber]>;

    VOTING_START_OFFSET(overrides?: CallOverrides): Promise<[BigNumber]>;

    VOTING_YAY_END_OFFSET(overrides?: CallOverrides): Promise<[BigNumber]>;

    callVote(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    createProposal(
      _proposalDocument: PromiseOrValue<string>,
      _actions: Voting.CallStruct[],
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    executeProposal(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    getActions(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<[Voting.CallStructOutput[]]>;

    getSponsored(
      _id: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    getVotes(
      _id: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<[BigNumber]>;

    lastSponsored(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<
      [BigNumber, BigNumber] & {
        lastSponsorTime: BigNumber;
        proposalID: BigNumber;
      }
    >;

    proposals(
      arg0: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<
      [
        boolean,
        string,
        string,
        BigNumber,
        BigNumber,
        BigNumber,
        BigNumber,
        BigNumber,
        BigNumber,
        BigNumber
      ] & {
        executed: boolean;
        proposer: string;
        proposalDocument: string;
        publishTime: BigNumber;
        voteCallTime: BigNumber;
        sponsorship: BigNumber;
        yayVotes: BigNumber;
        nayVotes: BigNumber;
        sponsorInterval: BigNumber;
        votingInterval: BigNumber;
      }
    >;

    proposalsLength(overrides?: CallOverrides): Promise<[BigNumber]>;

    setVotingKey(
      _votingKey: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    sponsorProposal(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    unsponsorProposal(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    vote(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _affirmative: PromiseOrValue<boolean>,
      _account: PromiseOrValue<string>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<ContractTransaction>;

    votingKey(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<[string]>;
  };

  DELEGATOR_CONTRACT(overrides?: CallOverrides): Promise<string>;

  EXECUTION_END_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

  EXECUTION_START_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

  PROPOSAL_SPONSOR_THRESHOLD(overrides?: CallOverrides): Promise<BigNumber>;

  QUORUM(overrides?: CallOverrides): Promise<BigNumber>;

  SPONSOR_LOCKOUT_TIME(overrides?: CallOverrides): Promise<BigNumber>;

  SPONSOR_WINDOW(overrides?: CallOverrides): Promise<BigNumber>;

  STAKING_CONTRACT(overrides?: CallOverrides): Promise<string>;

  VOTING_NAY_END_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

  VOTING_START_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

  VOTING_YAY_END_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

  callVote(
    _id: PromiseOrValue<BigNumberish>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  createProposal(
    _proposalDocument: PromiseOrValue<string>,
    _actions: Voting.CallStruct[],
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  executeProposal(
    _id: PromiseOrValue<BigNumberish>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  getActions(
    _id: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides
  ): Promise<Voting.CallStructOutput[]>;

  getSponsored(
    _id: PromiseOrValue<BigNumberish>,
    _account: PromiseOrValue<string>,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  getVotes(
    _id: PromiseOrValue<BigNumberish>,
    _account: PromiseOrValue<string>,
    overrides?: CallOverrides
  ): Promise<BigNumber>;

  lastSponsored(
    arg0: PromiseOrValue<string>,
    overrides?: CallOverrides
  ): Promise<
    [BigNumber, BigNumber] & {
      lastSponsorTime: BigNumber;
      proposalID: BigNumber;
    }
  >;

  proposals(
    arg0: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides
  ): Promise<
    [
      boolean,
      string,
      string,
      BigNumber,
      BigNumber,
      BigNumber,
      BigNumber,
      BigNumber,
      BigNumber,
      BigNumber
    ] & {
      executed: boolean;
      proposer: string;
      proposalDocument: string;
      publishTime: BigNumber;
      voteCallTime: BigNumber;
      sponsorship: BigNumber;
      yayVotes: BigNumber;
      nayVotes: BigNumber;
      sponsorInterval: BigNumber;
      votingInterval: BigNumber;
    }
  >;

  proposalsLength(overrides?: CallOverrides): Promise<BigNumber>;

  setVotingKey(
    _votingKey: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  sponsorProposal(
    _id: PromiseOrValue<BigNumberish>,
    _amount: PromiseOrValue<BigNumberish>,
    _account: PromiseOrValue<string>,
    _hint: PromiseOrValue<BigNumberish>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  unsponsorProposal(
    _id: PromiseOrValue<BigNumberish>,
    _amount: PromiseOrValue<BigNumberish>,
    _account: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  vote(
    _id: PromiseOrValue<BigNumberish>,
    _amount: PromiseOrValue<BigNumberish>,
    _affirmative: PromiseOrValue<boolean>,
    _account: PromiseOrValue<string>,
    _hint: PromiseOrValue<BigNumberish>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ContractTransaction>;

  votingKey(
    arg0: PromiseOrValue<string>,
    overrides?: CallOverrides
  ): Promise<string>;

  callStatic: {
    DELEGATOR_CONTRACT(overrides?: CallOverrides): Promise<string>;

    EXECUTION_END_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    EXECUTION_START_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    PROPOSAL_SPONSOR_THRESHOLD(overrides?: CallOverrides): Promise<BigNumber>;

    QUORUM(overrides?: CallOverrides): Promise<BigNumber>;

    SPONSOR_LOCKOUT_TIME(overrides?: CallOverrides): Promise<BigNumber>;

    SPONSOR_WINDOW(overrides?: CallOverrides): Promise<BigNumber>;

    STAKING_CONTRACT(overrides?: CallOverrides): Promise<string>;

    VOTING_NAY_END_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    VOTING_START_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    VOTING_YAY_END_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    callVote(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<void>;

    createProposal(
      _proposalDocument: PromiseOrValue<string>,
      _actions: Voting.CallStruct[],
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    executeProposal(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<void>;

    getActions(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<Voting.CallStructOutput[]>;

    getSponsored(
      _id: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    getVotes(
      _id: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    lastSponsored(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<
      [BigNumber, BigNumber] & {
        lastSponsorTime: BigNumber;
        proposalID: BigNumber;
      }
    >;

    proposals(
      arg0: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<
      [
        boolean,
        string,
        string,
        BigNumber,
        BigNumber,
        BigNumber,
        BigNumber,
        BigNumber,
        BigNumber,
        BigNumber
      ] & {
        executed: boolean;
        proposer: string;
        proposalDocument: string;
        publishTime: BigNumber;
        voteCallTime: BigNumber;
        sponsorship: BigNumber;
        yayVotes: BigNumber;
        nayVotes: BigNumber;
        sponsorInterval: BigNumber;
        votingInterval: BigNumber;
      }
    >;

    proposalsLength(overrides?: CallOverrides): Promise<BigNumber>;

    setVotingKey(
      _votingKey: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<void>;

    sponsorProposal(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<void>;

    unsponsorProposal(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<void>;

    vote(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _affirmative: PromiseOrValue<boolean>,
      _account: PromiseOrValue<string>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<void>;

    votingKey(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<string>;
  };

  filters: {
    "Execution(uint256)"(
      id?: PromiseOrValue<BigNumberish> | null
    ): ExecutionEventFilter;
    Execution(id?: PromiseOrValue<BigNumberish> | null): ExecutionEventFilter;

    "Proposal(uint256,address)"(
      id?: PromiseOrValue<BigNumberish> | null,
      proposer?: PromiseOrValue<string> | null
    ): ProposalEventFilter;
    Proposal(
      id?: PromiseOrValue<BigNumberish> | null,
      proposer?: PromiseOrValue<string> | null
    ): ProposalEventFilter;

    "Sponsorship(uint256,address,uint256)"(
      id?: PromiseOrValue<BigNumberish> | null,
      sponsor?: PromiseOrValue<string> | null,
      amount?: null
    ): SponsorshipEventFilter;
    Sponsorship(
      id?: PromiseOrValue<BigNumberish> | null,
      sponsor?: PromiseOrValue<string> | null,
      amount?: null
    ): SponsorshipEventFilter;

    "SponsorshipRevocation(uint256,address,uint256)"(
      id?: PromiseOrValue<BigNumberish> | null,
      sponsor?: PromiseOrValue<string> | null,
      amount?: null
    ): SponsorshipRevocationEventFilter;
    SponsorshipRevocation(
      id?: PromiseOrValue<BigNumberish> | null,
      sponsor?: PromiseOrValue<string> | null,
      amount?: null
    ): SponsorshipRevocationEventFilter;

    "VoteCall(uint256)"(
      id?: PromiseOrValue<BigNumberish> | null
    ): VoteCallEventFilter;
    VoteCall(id?: PromiseOrValue<BigNumberish> | null): VoteCallEventFilter;

    "VoteCast(uint256,address,bool,uint256)"(
      id?: PromiseOrValue<BigNumberish> | null,
      voter?: PromiseOrValue<string> | null,
      affirmative?: null,
      votes?: null
    ): VoteCastEventFilter;
    VoteCast(
      id?: PromiseOrValue<BigNumberish> | null,
      voter?: PromiseOrValue<string> | null,
      affirmative?: null,
      votes?: null
    ): VoteCastEventFilter;

    "VoteKeySet(address,address)"(
      account?: PromiseOrValue<string> | null,
      votingKey?: null
    ): VoteKeySetEventFilter;
    VoteKeySet(
      account?: PromiseOrValue<string> | null,
      votingKey?: null
    ): VoteKeySetEventFilter;
  };

  estimateGas: {
    DELEGATOR_CONTRACT(overrides?: CallOverrides): Promise<BigNumber>;

    EXECUTION_END_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    EXECUTION_START_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    PROPOSAL_SPONSOR_THRESHOLD(overrides?: CallOverrides): Promise<BigNumber>;

    QUORUM(overrides?: CallOverrides): Promise<BigNumber>;

    SPONSOR_LOCKOUT_TIME(overrides?: CallOverrides): Promise<BigNumber>;

    SPONSOR_WINDOW(overrides?: CallOverrides): Promise<BigNumber>;

    STAKING_CONTRACT(overrides?: CallOverrides): Promise<BigNumber>;

    VOTING_NAY_END_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    VOTING_START_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    VOTING_YAY_END_OFFSET(overrides?: CallOverrides): Promise<BigNumber>;

    callVote(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    createProposal(
      _proposalDocument: PromiseOrValue<string>,
      _actions: Voting.CallStruct[],
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    executeProposal(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    getActions(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    getSponsored(
      _id: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    getVotes(
      _id: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    lastSponsored(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    proposals(
      arg0: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    proposalsLength(overrides?: CallOverrides): Promise<BigNumber>;

    setVotingKey(
      _votingKey: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    sponsorProposal(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    unsponsorProposal(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    vote(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _affirmative: PromiseOrValue<boolean>,
      _account: PromiseOrValue<string>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<BigNumber>;

    votingKey(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<BigNumber>;
  };

  populateTransaction: {
    DELEGATOR_CONTRACT(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    EXECUTION_END_OFFSET(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    EXECUTION_START_OFFSET(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    PROPOSAL_SPONSOR_THRESHOLD(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    QUORUM(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    SPONSOR_LOCKOUT_TIME(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    SPONSOR_WINDOW(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    STAKING_CONTRACT(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    VOTING_NAY_END_OFFSET(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    VOTING_START_OFFSET(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    VOTING_YAY_END_OFFSET(
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    callVote(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    createProposal(
      _proposalDocument: PromiseOrValue<string>,
      _actions: Voting.CallStruct[],
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    executeProposal(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    getActions(
      _id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    getSponsored(
      _id: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    getVotes(
      _id: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    lastSponsored(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    proposals(
      arg0: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    proposalsLength(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    setVotingKey(
      _votingKey: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    sponsorProposal(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    unsponsorProposal(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _account: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    vote(
      _id: PromiseOrValue<BigNumberish>,
      _amount: PromiseOrValue<BigNumberish>,
      _affirmative: PromiseOrValue<boolean>,
      _account: PromiseOrValue<string>,
      _hint: PromiseOrValue<BigNumberish>,
      overrides?: Overrides & { from?: PromiseOrValue<string> }
    ): Promise<PopulatedTransaction>;

    votingKey(
      arg0: PromiseOrValue<string>,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;
  };
}
