export type SupportedLanguage = 'java' | 'javascript' | 'typescript';

export type VulnerabilityType = 'XSS' | 'SQL_INJECTION' | 'NOSQL_INJECTION';

export interface VulnerabilityFinding {
  language: SupportedLanguage;
  filePath: string;
  line: number;
  column: number;
  type: VulnerabilityType;
  message: string;
  codeSnippet: string;
}
