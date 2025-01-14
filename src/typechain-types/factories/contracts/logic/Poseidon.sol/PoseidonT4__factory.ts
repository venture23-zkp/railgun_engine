/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type { PromiseOrValue } from "../../../../common";
import type {
  PoseidonT4,
  PoseidonT4Interface,
} from "../../../../contracts/logic/Poseidon.sol/PoseidonT4";

const _abi = [
  {
    inputs: [
      {
        internalType: "bytes32[3]",
        name: "input",
        type: "bytes32[3]",
      },
    ],
    name: "poseidon",
    outputs: [
      {
        internalType: "bytes32",
        name: "",
        type: "bytes32",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
];

const _bytecode =
  "0x61013061003a600b82828239805160001a60731461002d57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe730000000000000000000000000000000000000000301460806040526004361060335760003560e01c80635a53025d146038575b600080fd5b60496043366004605b565b50600090565b60405190815260200160405180910390f35b600060608284031215606c57600080fd5b82601f830112607a57600080fd5b6040516060810181811067ffffffffffffffff8211171560c3577f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b60405280606084018581111560d757600080fd5b845b8181101560ef57803583526020928301920160d9565b50919594505050505056fea26469706673582212200bd1151b140f2e002fb547241654c556bddb234dedae858fd91ce1a942c1813064736f6c63430008110033";

type PoseidonT4ConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: PoseidonT4ConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class PoseidonT4__factory extends ContractFactory {
  constructor(...args: PoseidonT4ConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override deploy(
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<PoseidonT4> {
    return super.deploy(overrides || {}) as Promise<PoseidonT4>;
  }
  override getDeployTransaction(
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  override attach(address: string): PoseidonT4 {
    return super.attach(address) as PoseidonT4;
  }
  override connect(signer: Signer): PoseidonT4__factory {
    return super.connect(signer) as PoseidonT4__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): PoseidonT4Interface {
    return new utils.Interface(_abi) as PoseidonT4Interface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): PoseidonT4 {
    return new Contract(address, _abi, signerOrProvider) as PoseidonT4;
  }
}
