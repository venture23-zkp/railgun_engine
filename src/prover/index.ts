// @ts-ignore-next-line
import { groth16 } from "snarkjs";

export type Artifacts = {
  zkey: ArrayLike<number>;
  wasm: ArrayLike<number>;
  vkey: object;
};

const enum Circuits {
  OneTwo,
  OneThree,
  TwoTwo,
  TwoThree,
  EightTwo
}

export type Proof = {
  a: string[];
  b: string[][];
  c: string[];
};

export type PublicInputs = {
  merkleRoot: bigint;
  boundParamsHash: bigint;
  nullifiers: bigint[];
  commitmentsOut: bigint[];
};

export type PrivateInputs = {
  token: bigint;
  publicKey: [bigint, bigint]; 
  signature: [bigint, bigint, bigint];
  randomIn: bigint[];
  valueIn: bigint[];
  pathElements: bigint[][];
  leavesIndices: bigint[];
  nullifyingKey: bigint;
  npkOut: bigint[];
  valueOut: bigint[];
};

export type FormattedCircuitInputs = {
  [key: string]: bigint | bigint[];
};

// eslint-disable-next-line no-unused-vars
export type ArtifactsGetter = (circuit: Circuits) => Promise<Artifacts>;

class Prover {
  artifactsGetter: ArtifactsGetter;

  constructor(artifactsGetter: ArtifactsGetter) {
    this.artifactsGetter = artifactsGetter;
  }

  async verify(
    circuit: Circuits,
    inputs: PublicInputs,
    proof: Proof
  ): Promise<boolean> {
    // Fetch artifacts
    const artifacts = await this.artifactsGetter(circuit);
    // Return output of groth16 verify
    return groth16.verify(artifacts.vkey, inputs, proof);
  }

  async prove(
    circuit: Circuits,
    publicInputs: PublicInputs,
    privateInputs: PrivateInputs
  ): Promise<{ proof: Proof; publicInputs: PublicInputs }> {
    // Fetch artifacts
    const artifacts = await this.artifactsGetter(circuit);

    // Get formatted inputs
    const formattedInputs = Prover.formatInputs(publicInputs, privateInputs);

    // Generate proof
    const { proof } = await groth16.fullProve(
      formattedInputs,
      artifacts.wasm,
      artifacts.zkey
    );

    // Throw if proof is invalid
    if (!(await this.verify(circuit, publicInputs, proof)))
      throw new Error("Proof generation failed");

    // Return proof with inputs
    return {
      proof,
      publicInputs
    };
  }

  static formatInputs(
    publicInputs: PublicInputs,
    privateInputs: PrivateInputs
  ): FormattedCircuitInputs {
    return {
      merkleRoot: publicInputs.merkleRoot,
      boundParamsHash: publicInputs.boundParamsHash,
      nullifiers: publicInputs.nullifiers,
      commitmentsOut: publicInputs.commitmentsOut,
      token: privateInputs.token,
      publicKey: privateInputs.publicKey,
      signature: privateInputs.signature,
      randomIn: privateInputs.randomIn,
      valueIn: privateInputs.valueIn,
      pathElements: privateInputs.pathElements.flat(2),
      leavesIndices: privateInputs.leavesIndices,
      nullifyingKey: privateInputs.nullifyingKey,
      npkOut: privateInputs.npkOut,
      valueOut: privateInputs.valueOut
    };
  }
}

export { Prover };
