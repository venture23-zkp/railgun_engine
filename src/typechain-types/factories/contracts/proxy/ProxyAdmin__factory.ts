/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type { PromiseOrValue } from "../../../common";
import type {
  ProxyAdmin,
  ProxyAdminInterface,
} from "../../../contracts/proxy/ProxyAdmin";

const _abi = [
  {
    inputs: [
      {
        internalType: "address",
        name: "_admin",
        type: "address",
      },
    ],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "previousOwner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "OwnershipTransferred",
    type: "event",
  },
  {
    inputs: [],
    name: "owner",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "contract PausableUpgradableProxy",
        name: "_proxy",
        type: "address",
      },
    ],
    name: "pause",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "renounceOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "transferOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "contract PausableUpgradableProxy",
        name: "_proxy",
        type: "address",
      },
      {
        internalType: "address",
        name: "_newOwner",
        type: "address",
      },
    ],
    name: "transferProxyOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "contract PausableUpgradableProxy",
        name: "_proxy",
        type: "address",
      },
    ],
    name: "unpause",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "contract PausableUpgradableProxy",
        name: "_proxy",
        type: "address",
      },
      {
        internalType: "address",
        name: "_newImplementation",
        type: "address",
      },
    ],
    name: "upgrade",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
];

const _bytecode =
  "0x608060405234801561001057600080fd5b5060405161064738038061064783398101604081905261002f9161017b565b61003833610051565b61004b816100a160201b61028e1760201c565b506101ab565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6100a961011f565b6001600160a01b0381166101135760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b60648201526084015b60405180910390fd5b61011c81610051565b50565b6000546001600160a01b031633146101795760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015260640161010a565b565b60006020828403121561018d57600080fd5b81516001600160a01b03811681146101a457600080fd5b9392505050565b61048d806101ba6000396000f3fe608060405234801561001057600080fd5b506004361061007c5760003560e01c806376a67a511161005b57806376a67a51146100b15780638da5cb5b146100c457806399a88ec4146100e3578063f2fde38b146100f657600080fd5b8062361d551461008157806357b001f914610096578063715018a6146100a9575b600080fd5b61009461008f3660046103fa565b610109565b005b6100946100a4366004610433565b61018a565b6100946101e8565b6100946100bf366004610433565b6101fc565b600054604080516001600160a01b039092168252519081900360200190f35b6100946100f13660046103fa565b61023f565b610094610104366004610433565b61028e565b610111610323565b6040517ff2fde38b0000000000000000000000000000000000000000000000000000000081526001600160a01b03828116600483015283169063f2fde38b906024015b600060405180830381600087803b15801561016e57600080fd5b505af1158015610182573d6000803e3d6000fd5b505050505050565b610192610323565b806001600160a01b0316633f4ba83a6040518163ffffffff1660e01b8152600401600060405180830381600087803b1580156101cd57600080fd5b505af11580156101e1573d6000803e3d6000fd5b5050505050565b6101f0610323565b6101fa600061037d565b565b610204610323565b806001600160a01b0316638456cb596040518163ffffffff1660e01b8152600401600060405180830381600087803b1580156101cd57600080fd5b610247610323565b6040517f0900f0100000000000000000000000000000000000000000000000000000000081526001600160a01b038281166004830152831690630900f01090602401610154565b610296610323565b6001600160a01b0381166103175760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201527f646472657373000000000000000000000000000000000000000000000000000060648201526084015b60405180910390fd5b6103208161037d565b50565b6000546001600160a01b031633146101fa5760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015260640161030e565b600080546001600160a01b038381167fffffffffffffffffffffffff0000000000000000000000000000000000000000831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6001600160a01b038116811461032057600080fd5b6000806040838503121561040d57600080fd5b8235610418816103e5565b91506020830135610428816103e5565b809150509250929050565b60006020828403121561044557600080fd5b8135610450816103e5565b939250505056fea2646970667358221220bc1a5effbf7da56428aa10da264a9fd55641ea2df4075e52a83a975c84b26ff164736f6c634300080c0033";

type ProxyAdminConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: ProxyAdminConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class ProxyAdmin__factory extends ContractFactory {
  constructor(...args: ProxyAdminConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override deploy(
    _admin: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<ProxyAdmin> {
    return super.deploy(_admin, overrides || {}) as Promise<ProxyAdmin>;
  }
  override getDeployTransaction(
    _admin: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(_admin, overrides || {});
  }
  override attach(address: string): ProxyAdmin {
    return super.attach(address) as ProxyAdmin;
  }
  override connect(signer: Signer): ProxyAdmin__factory {
    return super.connect(signer) as ProxyAdmin__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): ProxyAdminInterface {
    return new utils.Interface(_abi) as ProxyAdminInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): ProxyAdmin {
    return new Contract(address, _abi, signerOrProvider) as ProxyAdmin;
  }
}
