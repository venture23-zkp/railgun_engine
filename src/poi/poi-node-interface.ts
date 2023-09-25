import { Chain } from '../models/engine-types';
import { BlindedCommitmentData, POIEngineProofInputs, POIsPerList } from '../models/poi-types';

export abstract class POINodeInterface {
  abstract isActive(chain: Chain): boolean;

  abstract getPOIsPerList(
    chain: Chain,
    listKeys: string[],
    blindedCommitmentDatas: BlindedCommitmentData[],
  ): Promise<{ [blindedCommitment: string]: POIsPerList }>;

  abstract generateAndSubmitPOI(
    chain: Chain,
    listKey: string,
    proofInputs: POIEngineProofInputs,
    blindedCommitmentsOut: string[],
    txidMerklerootIndex: number,
    railgunTransactionBlockNumber: number,
  ): Promise<void>;
}
