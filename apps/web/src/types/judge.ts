export interface JudgeStep {
  index: number;
  title: string;
  timeRange: string;
  summary: string;
  proofSnippet: string;
  speakerNotes: string;
  metrics: Array<{ label: string; value: string }>;
}
