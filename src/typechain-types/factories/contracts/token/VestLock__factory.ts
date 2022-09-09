/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type { PromiseOrValue } from "../../../common";
import type {
  VestLock,
  VestLockInterface,
} from "../../../contracts/token/VestLock";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "uint8",
        name: "version",
        type: "uint8",
      },
    ],
    name: "Initialized",
    type: "event",
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
    name: "admin",
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
        internalType: "address",
        name: "_contract",
        type: "address",
      },
      {
        internalType: "bytes",
        name: "_data",
        type: "bytes",
      },
      {
        internalType: "uint256",
        name: "_value",
        type: "uint256",
      },
    ],
    name: "callContract",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "_id",
        type: "uint256",
      },
    ],
    name: "claim",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "_id",
        type: "uint256",
      },
      {
        internalType: "address",
        name: "_delegatee",
        type: "address",
      },
    ],
    name: "delegate",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "_admin",
        type: "address",
      },
      {
        internalType: "address",
        name: "_beneficiary",
        type: "address",
      },
      {
        internalType: "contract Staking",
        name: "_staking",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "_releaseTime",
        type: "uint256",
      },
    ],
    name: "initialize",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "_newLocktime",
        type: "uint256",
      },
    ],
    name: "overrideLock",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
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
    inputs: [],
    name: "releaseTime",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
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
        internalType: "contract IERC20",
        name: "_token",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "_amount",
        type: "uint256",
      },
    ],
    name: "stake",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "staking",
    outputs: [
      {
        internalType: "contract Staking",
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
        internalType: "contract IERC20",
        name: "_token",
        type: "address",
      },
      {
        internalType: "address",
        name: "_to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "_amount",
        type: "uint256",
      },
    ],
    name: "transferERC20",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address payable",
        name: "_to",
        type: "address",
      },
      {
        internalType: "uint256",
        name: "_amount",
        type: "uint256",
      },
    ],
    name: "transferETH",
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
        internalType: "uint256",
        name: "_id",
        type: "uint256",
      },
    ],
    name: "unlock",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    stateMutability: "payable",
    type: "receive",
  },
];

const _bytecode =
  "0x608060405234801561001057600080fd5b5061145b806100206000396000f3fe6080604052600436106100ec5760003560e01c80639db5dbe41161008a578063c6b295c111610059578063c6b295c11461026e578063cf756fdf1461028e578063f2fde38b146102ae578063f851a440146102ce57600080fd5b80639db5dbe4146101ea578063adc9772e1461020a578063b91d40011461022a578063c05647531461024e57600080fd5b80636198e339116100c65780636198e33914610177578063715018a6146101975780637b1a4909146101ac5780638da5cb5b146101cc57600080fd5b806308bbb824146100f8578063379607f51461011a5780634cf088d91461013a57600080fd5b366100f357005b600080fd5b34801561010457600080fd5b506101186101133660046111ac565b6102ee565b005b34801561012657600080fd5b506101186101353660046111dc565b610379565b34801561014657600080fd5b5060665461015a906001600160a01b031681565b6040516001600160a01b0390911681526020015b60405180910390f35b34801561018357600080fd5b506101186101923660046111dc565b6103fc565b3480156101a357600080fd5b5061011861044e565b3480156101b857600080fd5b506101186101c73660046111f5565b610462565b3480156101d857600080fd5b506033546001600160a01b031661015a565b3480156101f657600080fd5b50610118610205366004611221565b610574565b34801561021657600080fd5b506101186102253660046111f5565b6105ed565b34801561023657600080fd5b5061024060655481565b60405190815260200161016e565b34801561025a57600080fd5b506101186102693660046111dc565b61073b565b34801561027a57600080fd5b50610118610289366004611262565b610811565b34801561029a57600080fd5b506101186102a93660046112ed565b61094c565b3480156102ba57600080fd5b506101186102c936600461133e565b610acd565b3480156102da57600080fd5b5060675461015a906001600160a01b031681565b6102f6610b5d565b6066546040517f08bbb824000000000000000000000000000000000000000000000000000000008152600481018490526001600160a01b038381166024830152909116906308bbb82490604401600060405180830381600087803b15801561035d57600080fd5b505af1158015610371573d6000803e3d6000fd5b505050505050565b610381610b5d565b6066546040517f379607f5000000000000000000000000000000000000000000000000000000008152600481018390526001600160a01b039091169063379607f5906024015b600060405180830381600087803b1580156103e157600080fd5b505af11580156103f5573d6000803e3d6000fd5b5050505050565b610404610b5d565b6066546040517f6198e339000000000000000000000000000000000000000000000000000000008152600481018390526001600160a01b0390911690636198e339906024016103c7565b610456610b5d565b6104606000610bb7565b565b60655442116104c45760405162461bcd60e51b8152602060048201526024808201527f566573744c6f636b3a2056657374696e67206861736e2774206d617475726564604482015263081e595d60e21b60648201526084015b60405180910390fd5b6104cc610b5d565b6000826001600160a01b03168260405160006040518083038185875af1925050503d8060008114610519576040519150601f19603f3d011682016040523d82523d6000602084013e61051e565b606091505b505090508061056f5760405162461bcd60e51b815260206004820152601460248201527f4661696c656420746f2073656e6420457468657200000000000000000000000060448201526064016104bb565b505050565b60655442116105d15760405162461bcd60e51b8152602060048201526024808201527f566573744c6f636b3a2056657374696e67206861736e2774206d617475726564604482015263081e595d60e21b60648201526084016104bb565b6105d9610b5d565b61056f6001600160a01b0384168383610c16565b6105f5610b5d565b60665461060f906001600160a01b03848116911683610cbf565b6066546040517fa694fc3a000000000000000000000000000000000000000000000000000000008152600481018390526000916001600160a01b03169063a694fc3a906024016020604051808303816000875af1158015610674573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610698919061135b565b6066549091506001600160a01b03166308bbb824826106bf6033546001600160a01b031690565b6040517fffffffff0000000000000000000000000000000000000000000000000000000060e085901b16815260048101929092526001600160a01b03166024820152604401600060405180830381600087803b15801561071e57600080fd5b505af1158015610732573d6000803e3d6000fd5b50505050505050565b6067546001600160a01b031633146107955760405162461bcd60e51b815260206004820152601a60248201527f566573744c6f636b3a2043616c6c6572206e6f742061646d696e00000000000060448201526064016104bb565b606554811061080c5760405162461bcd60e51b815260206004820152603760248201527f566573744c6f636b3a206e6577206c6f636b2074696d65206d7573742062652060448201527f6c657373207468616e206f6c64206c6f636b2074696d6500000000000000000060648201526084016104bb565b606555565b606554421161086e5760405162461bcd60e51b8152602060048201526024808201527f566573744c6f636b3a2056657374696e67206861736e2774206d617475726564604482015263081e595d60e21b60648201526084016104bb565b610876610b5d565b6000846001600160a01b0316828585604051610893929190611374565b60006040518083038185875af1925050503d80600081146108d0576040519150601f19603f3d011682016040523d82523d6000602084013e6108d5565b606091505b50509050806103f55760405162461bcd60e51b815260206004820152602b60248201527f566573744c6f636b3a206661696c757265206f6e2065787465726e616c20636f60448201527f6e74726163742063616c6c00000000000000000000000000000000000000000060648201526084016104bb565b600054610100900460ff161580801561096c5750600054600160ff909116105b806109865750303b158015610986575060005460ff166001145b6109f85760405162461bcd60e51b815260206004820152602e60248201527f496e697469616c697a61626c653a20636f6e747261637420697320616c72656160448201527f647920696e697469616c697a656400000000000000000000000000000000000060648201526084016104bb565b6000805460ff191660011790558015610a1b576000805461ff0019166101001790555b6067805473ffffffffffffffffffffffffffffffffffffffff19166001600160a01b038716179055610a4b610e0d565b610a5484610acd565b6066805473ffffffffffffffffffffffffffffffffffffffff19166001600160a01b038516179055606582905580156103f5576000805461ff0019169055604051600181527f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb38474024989060200160405180910390a15050505050565b610ad5610b5d565b6001600160a01b038116610b515760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201527f646472657373000000000000000000000000000000000000000000000000000060648201526084016104bb565b610b5a81610bb7565b50565b6033546001600160a01b031633146104605760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657260448201526064016104bb565b603380546001600160a01b0383811673ffffffffffffffffffffffffffffffffffffffff19831681179093556040519116919082907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a35050565b6040516001600160a01b03831660248201526044810182905261056f9084907fa9059cbb00000000000000000000000000000000000000000000000000000000906064015b60408051601f198184030181529190526020810180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167fffffffff0000000000000000000000000000000000000000000000000000000090931692909217909152610e92565b801580610d5257506040517fdd62ed3e0000000000000000000000000000000000000000000000000000000081523060048201526001600160a01b03838116602483015284169063dd62ed3e90604401602060405180830381865afa158015610d2c573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610d50919061135b565b155b610dc45760405162461bcd60e51b815260206004820152603660248201527f5361666545524332303a20617070726f76652066726f6d206e6f6e2d7a65726f60448201527f20746f206e6f6e2d7a65726f20616c6c6f77616e63650000000000000000000060648201526084016104bb565b6040516001600160a01b03831660248201526044810182905261056f9084907f095ea7b30000000000000000000000000000000000000000000000000000000090606401610c5b565b600054610100900460ff16610e8a5760405162461bcd60e51b815260206004820152602b60248201527f496e697469616c697a61626c653a20636f6e7472616374206973206e6f74206960448201527f6e697469616c697a696e6700000000000000000000000000000000000000000060648201526084016104bb565b610460610f77565b6000610ee7826040518060400160405280602081526020017f5361666545524332303a206c6f772d6c6576656c2063616c6c206661696c6564815250856001600160a01b0316610ffd9092919063ffffffff16565b80519091501561056f5780806020019051810190610f059190611384565b61056f5760405162461bcd60e51b815260206004820152602a60248201527f5361666545524332303a204552433230206f7065726174696f6e20646964206e60448201527f6f7420737563636565640000000000000000000000000000000000000000000060648201526084016104bb565b600054610100900460ff16610ff45760405162461bcd60e51b815260206004820152602b60248201527f496e697469616c697a61626c653a20636f6e7472616374206973206e6f74206960448201527f6e697469616c697a696e6700000000000000000000000000000000000000000060648201526084016104bb565b61046033610bb7565b606061100c8484600085611016565b90505b9392505050565b60608247101561108e5760405162461bcd60e51b815260206004820152602660248201527f416464726573733a20696e73756666696369656e742062616c616e636520666f60448201527f722063616c6c000000000000000000000000000000000000000000000000000060648201526084016104bb565b6001600160a01b0385163b6110e55760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e747261637400000060448201526064016104bb565b600080866001600160a01b0316858760405161110191906113d6565b60006040518083038185875af1925050503d806000811461113e576040519150601f19603f3d011682016040523d82523d6000602084013e611143565b606091505b509150915061115382828661115e565b979650505050505050565b6060831561116d57508161100f565b82511561117d5782518084602001fd5b8160405162461bcd60e51b81526004016104bb91906113f2565b6001600160a01b0381168114610b5a57600080fd5b600080604083850312156111bf57600080fd5b8235915060208301356111d181611197565b809150509250929050565b6000602082840312156111ee57600080fd5b5035919050565b6000806040838503121561120857600080fd5b823561121381611197565b946020939093013593505050565b60008060006060848603121561123657600080fd5b833561124181611197565b9250602084013561125181611197565b929592945050506040919091013590565b6000806000806060858703121561127857600080fd5b843561128381611197565b9350602085013567ffffffffffffffff808211156112a057600080fd5b818701915087601f8301126112b457600080fd5b8135818111156112c357600080fd5b8860208285010111156112d557600080fd5b95986020929092019750949560400135945092505050565b6000806000806080858703121561130357600080fd5b843561130e81611197565b9350602085013561131e81611197565b9250604085013561132e81611197565b9396929550929360600135925050565b60006020828403121561135057600080fd5b813561100f81611197565b60006020828403121561136d57600080fd5b5051919050565b8183823760009101908152919050565b60006020828403121561139657600080fd5b8151801515811461100f57600080fd5b60005b838110156113c15781810151838201526020016113a9565b838111156113d0576000848401525b50505050565b600082516113e88184602087016113a6565b9190910192915050565b60208152600082518060208401526114118160408501602087016113a6565b601f01601f1916919091016040019291505056fea2646970667358221220ae44d3751fdeb9796e24f8592cf5c02274f546cd61085481b4e61077a6be3d4964736f6c634300080c0033";

type VestLockConstructorParams =
  | [signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: VestLockConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => xs.length > 1;

export class VestLock__factory extends ContractFactory {
  constructor(...args: VestLockConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      super(_abi, _bytecode, args[0]);
    }
  }

  override deploy(
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<VestLock> {
    return super.deploy(overrides || {}) as Promise<VestLock>;
  }
  override getDeployTransaction(
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  override attach(address: string): VestLock {
    return super.attach(address) as VestLock;
  }
  override connect(signer: Signer): VestLock__factory {
    return super.connect(signer) as VestLock__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): VestLockInterface {
    return new utils.Interface(_abi) as VestLockInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): VestLock {
    return new Contract(address, _abi, signerOrProvider) as VestLock;
  }
}