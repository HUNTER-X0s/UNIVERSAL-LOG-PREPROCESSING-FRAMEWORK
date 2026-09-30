export type ParserTier = 'Tier A' | 'Tier B' | 'Tier C';

export interface InternetSample {
  label: string;
  payload: string;
  description: string;
}

export interface ParserEntry {
  id: string;
  name: string;
  vendor: string;
  tier: ParserTier;
  category: string;
  format: string;
  status: 'VERIFIED' | 'STABLE' | 'OPERATIONAL';
  testsPassed: string;
  throughputEps: number;
  p99LatencyMs: number;
  residuePreserved: boolean;
  sampleLog: string;
  ocsfClass: string;
  ocsfClassId: number;
  redosSafety: string;
  supportedFormats: string[];
  supportedVendors: string[];
  description: string;
  targetFields: string[];
  mappedFieldsCount: number;
  internetSamples?: InternetSample[];
}
