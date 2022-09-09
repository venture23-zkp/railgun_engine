/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import { Signer, utils, Contract, ContractFactory, Overrides } from "ethers";
import type { Provider, TransactionRequest } from "@ethersproject/providers";
import type { PromiseOrValue } from "../../../../common";
import type {
  CommitmentsStub,
  CommitmentsStubInterface,
} from "../../../../contracts/teststubs/logic/CommitmentsStub";

const _abi = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
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
    inputs: [],
    name: "ZERO_VALUE",
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
    inputs: [
      {
        internalType: "uint256",
        name: "_left",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "_right",
        type: "uint256",
      },
    ],
    name: "hashLeftRight",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256[]",
        name: "_leafHashes",
        type: "uint256[]",
      },
    ],
    name: "insertLeavesStub",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "merkleRoot",
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
    inputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    name: "nullifiers",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    name: "rootHistory",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "treeNumber",
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
    inputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    name: "zeros",
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
];

const _bytecode =
  "0x60806040523480156200001157600080fd5b506200001c62000022565b6200041b565b600054610100900460ff1615808015620000435750600054600160ff909116105b8062000073575062000060306200015f60201b6200027e1760201c565b15801562000073575060005460ff166001145b620000dc5760405162461bcd60e51b815260206004820152602e60248201527f496e697469616c697a61626c653a20636f6e747261637420697320616c72656160448201526d191e481a5b9a5d1a585b1a5e995960921b60648201526084015b60405180910390fd5b6000805460ff19166001179055801562000100576000805461ff0019166101001790555b620001156200016e60201b6200029a1760201c565b80156200015c576000805461ff0019169055604051600181527f7f26b83ff96e1f2b6a682f133852f6798a09c465da95921460cefb38474024989060200160405180910390a15b50565b6001600160a01b03163b151590565b600054610100900460ff16620001db5760405162461bcd60e51b815260206004820152602b60248201527f496e697469616c697a61626c653a20636f6e7472616374206973206e6f74206960448201526a6e697469616c697a696e6760a81b6064820152608401620000d3565b620002167f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000160008051602062000e2f8339815191526200036b565b6006556000620002567f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f000000160008051602062000e2f8339815191526200036b565b905060005b6010811015620002a15781600682601081106200027c576200027c6200038e565b01556200028a8280620002d4565b9150806200029881620003a4565b9150506200025b565b5060038190556004819055600554600090815260266020908152604080832093835292905220805460ff19166001179055565b6040805180820182528381526020810183905290516314d2f97b60e11b815260009173__$6e606460795bf5f7b62cf6c7a6a553ac5e$__916329a5f2f6916200032091600401620003ce565b602060405180830381865af41580156200033e573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019062000364919062000401565b9392505050565b6000826200038957634e487b7160e01b600052601260045260246000fd5b500690565b634e487b7160e01b600052603260045260246000fd5b6000600019821415620003c757634e487b7160e01b600052601160045260246000fd5b5060010190565b60408101818360005b6002811015620003f8578151835260209283019290910190600101620003d7565b50505092915050565b6000602082840312156200041457600080fd5b5051919050565b610a04806200042b6000396000f3fe608060405234801561001057600080fd5b50600436106100885760003560e01c806378d3915c1161005b57806378d3915c14610103578063e829558814610131578063ec73295914610144578063f0f2cf391461014c57600080fd5b80632eb4a7ab1461008d57806338953305146100a95780635bb93995146100e757806366503315146100fa575b600080fd5b61009660035481565b6040519081526020015b60405180910390f35b6100d76100b73660046106ed565b602660209081526000928352604080842090915290825290205460ff1681565b60405190151581526020016100a0565b6100966100f53660046106ed565b610161565b61009660055481565b6100d76101113660046106ed565b600160209081526000928352604080842090915290825290205460ff1681565b61009661013f36600461070f565b61020e565b610096610225565b61015f61015a36600461073e565b610272565b005b6040805180820182528381526020810183905290517f29a5f2f600000000000000000000000000000000000000000000000000000000815260009173__$6e606460795bf5f7b62cf6c7a6a553ac5e$__916329a5f2f6916101c4916004016107fc565b602060405180830381865af41580156101e1573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610205919061082d565b90505b92915050565b6006816010811061021e57600080fd5b0154905081565b61026f7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000017f95b5e3f3c951508f13e7771152f5b7c7329a294917685c10a571c9247e3b9fff610846565b81565b61027b81610443565b50565b73ffffffffffffffffffffffffffffffffffffffff163b151590565b600054610100900460ff16610335576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602b60248201527f496e697469616c697a61626c653a20636f6e7472616374206973206e6f74206960448201527f6e697469616c697a696e67000000000000000000000000000000000000000000606482015260840160405180910390fd5b61037f7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000017f95b5e3f3c951508f13e7771152f5b7c7329a294917685c10a571c9247e3b9fff610846565b60065560006103ce7f30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f00000017f95b5e3f3c951508f13e7771152f5b7c7329a294917685c10a571c9247e3b9fff610846565b905060005b60108110156104105781600682601081106103f0576103f0610868565b01556103fc8280610161565b91508061040881610894565b9150506103d3565b5060038190556004819055600554600090815260266020908152604080832093835292905220805460ff19166001179055565b805161045160106002610993565b8160025461045f919061099f565b1061046c5761046c6106cb565b60028054908290600061047f838561099f565b909155506000905080805b601081101561067a57600184901c915060006104a7600286610846565b6001141561052e576104bd83600187901c6109b7565b93506104f6601683601081106104d5576104d5610868565b01548883815181106104e9576104e9610868565b6020026020010151610161565b87858151811061050857610508610868565b602090810291909101015261051e60018261099f565b905061052b60018661099f565b94505b858110156106545760006105436001886109b7565b821015610575578761055683600161099f565b8151811061056657610566610868565b6020026020010151905061058d565b6006836010811061058857610588610868565b015490505b6105986001886109b7565b8214806105ae57506105ab6002886109b7565b82145b156105e3578782815181106105c5576105c5610868565b6020026020010151601684601081106105e0576105e0610868565b01555b6105f184600188901c6109b7565b945061061688838151811061060857610608610868565b602002602001015182610161565b88868151811061062857610628610868565b602090810291909101015261063e60028761099f565b955061064d905060028261099f565b905061052e565b829450836001610664919061099f565b955050808061067290610894565b91505061048a565b508460008151811061068e5761068e610868565b60209081029190910181015160038190556005546000908152602683526040808220928252919092529020805460ff191660011790555050505050565b6004546003556000600281905560058054916106e683610894565b9190505550565b6000806040838503121561070057600080fd5b50508035926020909101359150565b60006020828403121561072157600080fd5b5035919050565b634e487b7160e01b600052604160045260246000fd5b6000602080838503121561075157600080fd5b823567ffffffffffffffff8082111561076957600080fd5b818501915085601f83011261077d57600080fd5b81358181111561078f5761078f610728565b8060051b604051601f19603f830116810181811085821117156107b4576107b4610728565b6040529182528482019250838101850191888311156107d257600080fd5b938501935b828510156107f0578435845293850193928501926107d7565b98975050505050505050565b60408101818360005b6002811015610824578151835260209283019290910190600101610805565b50505092915050565b60006020828403121561083f57600080fd5b5051919050565b60008261086357634e487b7160e01b600052601260045260246000fd5b500690565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b60006000198214156108a8576108a861087e565b5060010190565b600181815b808511156108ea5781600019048211156108d0576108d061087e565b808516156108dd57918102915b93841c93908002906108b4565b509250929050565b60008261090157506001610208565b8161090e57506000610208565b8160018114610924576002811461092e5761094a565b6001915050610208565b60ff84111561093f5761093f61087e565b50506001821b610208565b5060208310610133831016604e8410600b841016171561096d575081810a610208565b61097783836108af565b806000190482111561098b5761098b61087e565b029392505050565b600061020583836108f2565b600082198211156109b2576109b261087e565b500190565b6000828210156109c9576109c961087e565b50039056fea2646970667358221220cf0caf25cc113cc4debf76ce7b2d80cde1dc87c387be487507a304cfb3cb341364736f6c634300080c003395b5e3f3c951508f13e7771152f5b7c7329a294917685c10a571c9247e3b9fff";

type CommitmentsStubConstructorParams =
  | [linkLibraryAddresses: CommitmentsStubLibraryAddresses, signer?: Signer]
  | ConstructorParameters<typeof ContractFactory>;

const isSuperArgs = (
  xs: CommitmentsStubConstructorParams
): xs is ConstructorParameters<typeof ContractFactory> => {
  return (
    typeof xs[0] === "string" ||
    (Array.isArray as (arg: any) => arg is readonly any[])(xs[0]) ||
    "_isInterface" in xs[0]
  );
};

export class CommitmentsStub__factory extends ContractFactory {
  constructor(...args: CommitmentsStubConstructorParams) {
    if (isSuperArgs(args)) {
      super(...args);
    } else {
      const [linkLibraryAddresses, signer] = args;
      super(
        _abi,
        CommitmentsStub__factory.linkBytecode(linkLibraryAddresses),
        signer
      );
    }
  }

  static linkBytecode(
    linkLibraryAddresses: CommitmentsStubLibraryAddresses
  ): string {
    let linkedBytecode = _bytecode;

    linkedBytecode = linkedBytecode.replace(
      new RegExp("__\\$6e606460795bf5f7b62cf6c7a6a553ac5e\\$__", "g"),
      linkLibraryAddresses["contracts/logic/Poseidon.sol:PoseidonT3"]
        .replace(/^0x/, "")
        .toLowerCase()
    );

    return linkedBytecode;
  }

  override deploy(
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): Promise<CommitmentsStub> {
    return super.deploy(overrides || {}) as Promise<CommitmentsStub>;
  }
  override getDeployTransaction(
    overrides?: Overrides & { from?: PromiseOrValue<string> }
  ): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  override attach(address: string): CommitmentsStub {
    return super.attach(address) as CommitmentsStub;
  }
  override connect(signer: Signer): CommitmentsStub__factory {
    return super.connect(signer) as CommitmentsStub__factory;
  }

  static readonly bytecode = _bytecode;
  static readonly abi = _abi;
  static createInterface(): CommitmentsStubInterface {
    return new utils.Interface(_abi) as CommitmentsStubInterface;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): CommitmentsStub {
    return new Contract(address, _abi, signerOrProvider) as CommitmentsStub;
  }
}

export interface CommitmentsStubLibraryAddresses {
  ["contracts/logic/Poseidon.sol:PoseidonT3"]: string;
}