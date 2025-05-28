import * as vscode from 'vscode';
import { analyzeJava } from './analyzers/javaAnalyzer';
import { analyzeJavaScript } from './analyzers/jsAnalyzer';
import { VulnerabilityFinding } from './types';

export function activate(context: vscode.ExtensionContext) {
  console.log('[sec-proj1] extension activated');
  const diagnosticCollection = vscode.languages.createDiagnosticCollection('sec-proj1');
  context.subscriptions.push(diagnosticCollection);

  const runAnalysis = async (document: vscode.TextDocument) => {
    const language = document.languageId;
    let findings: VulnerabilityFinding[] = [];

    console.log(`[sec-proj1] Running analysis for: ${language}`);

    try {
      if (language === 'java') {
        findings = await analyzeJava(document);
      } else if (
        language === 'javascript' ||
        language === 'typescript' ||
        language === 'javascriptreact' ||
        language === 'typescriptreact'
      ) {
        findings = await analyzeJavaScript(document);
      } else {
        console.log(`[sec-proj1] Skipping unsupported language: ${language}`);
        return;
      }
    } catch (err) {
      console.error('[sec-proj1] Analysis error:', err);
      return;
    }

    const diagnostics: vscode.Diagnostic[] = findings.map((finding) => {
      const range = new vscode.Range(
        finding.line,
        finding.column,
        finding.line,
        finding.column + finding.codeSnippet.length
      );
      const diagnostic = new vscode.Diagnostic(
        range,
        `[${finding.type}] ${finding.message}`,
        vscode.DiagnosticSeverity.Warning
      );
      diagnostic.source = 'sec-proj1';
      return diagnostic;
    });

    diagnosticCollection.set(document.uri, diagnostics);
  };

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(runAnalysis),
    vscode.workspace.onDidSaveTextDocument(runAnalysis)
  );

  if (vscode.window.activeTextEditor) {
    runAnalysis(vscode.window.activeTextEditor.document);
  }
}

export function deactivate() { }
