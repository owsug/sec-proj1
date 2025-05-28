import * as vscode from 'vscode';
import { getParser } from './utils/treeSitterLoader';
import { VulnerabilityFinding } from '../types';

export async function analyzeJava(document: vscode.TextDocument): Promise<VulnerabilityFinding[]> {
  const parser = getParser('java');
  const tree = parser.parse(document.getText());

  const findings: VulnerabilityFinding[] = [];
  const rootNode = tree.rootNode;

  const taintedVars = new Set<string>();
  const sanitizedVars = new Set<string>();
  const varAssignments = new Map<string, Set<string>>();
  const stringLiterals = new Set<string>();
  const sqlExecutionMethods = ['executeQuery', 'executeUpdate', 'execute'];

  const taintSources = [
    'getParameter', 'getHeader', 'getCookies', 'getInputStream', 'getParameterMap',
    'nextLine', 'readLine', 'getEnv', 'getProperty', 'getQueryString', 'getPathInfo',
    'getRemoteUser', 'getRequestedSessionId', 'getRequestURI', 'getRequestURL',
    'getServletPath', 'getServerName', 'getServerPort', 'getLocalName', 'getLocalPort'
  ];

  const sanitizers = [
    'HtmlUtils.htmlEscape',
    'StringEscapeUtils.escapeHtml',
    'URLEncoder.encode'
  ];

  console.log('[sec-proj1] Running JS analysis');
  console.log('[sec-proj1] AST:\n', rootNode.toString());

  function recordAssignment(target: string, sources: Set<string>) {
    if (!varAssignments.has(target)) {
      varAssignments.set(target, new Set());
    }
    sources.forEach((s) => varAssignments.get(target)!.add(s));
  }

  function isTainted(varName: string, visited = new Set<string>()): boolean {
    if (sanitizedVars.has(varName)) { return false; }
    if (taintedVars.has(varName)) { return true; }
    if (visited.has(varName)) { return false; }
    visited.add(varName);

    const deps = varAssignments.get(varName);
    if (!deps) { return false; }

    return Array.from(deps).some((d) => isTainted(d, visited));
  }

  function isSafeLiteralVariable(varName: string): boolean {
    return stringLiterals.has(varName);
  }

  const visit = (node: any) => {
    if (
      node.type === 'method_invocation' &&
      node.namedChildren.some((c: any) => c.type === 'identifier' && c.text === 'println')
    ) {
      const argList = node.namedChildren.find((c: any) => c.type === 'argument_list');
      const containsTaintCall = (n: any): boolean => {
        return (
          n.type === 'method_invocation' &&
          taintSources.includes(n.namedChildren[1]?.text)
        ) || (n.namedChildren || []).some(containsTaintCall);
      };
      if (argList && containsTaintCall(argList)) {
        const { startPosition, endPosition } = node;
        findings.push({
          language: 'java',
          filePath: document.uri.fsPath,
          line: startPosition.row,
          column: startPosition.column,
          type: 'XSS',
          message: 'Possible XSS: println with tainted input',
          codeSnippet: document.getText(new vscode.Range(
            startPosition.row, startPosition.column,
            endPosition.row, endPosition.column
          )),
        });
      }
    }

    if (node.type === 'local_variable_declaration') {
      const declarators = node.namedChildren.filter((c: any) => c.type === 'variable_declarator');
      for (const declarator of declarators) {
        const varName = declarator.namedChildren.find((c: any) => c.type === 'identifier')?.text;
        const valueNode = declarator.namedChildren.find((c: any) => c.type !== 'identifier');
        if (!varName || !valueNode) { continue; }

        if (valueNode.type === 'string_literal') {
          stringLiterals.add(varName);
          continue;
        }

        if (
          valueNode.type === 'method_invocation' &&
          taintSources.includes(valueNode.namedChildren[1]?.text)
        ) {
          taintedVars.add(varName);
        }

        const sources = new Set<string>();
        const collectIdentifiers = (n: any) => {
          if (n.type === 'identifier') {
            sources.add(n.text);
          }
          for (const child of n.namedChildren || []) {
            collectIdentifiers(child);
          }
        };
        collectIdentifiers(valueNode);

        if (sources.size > 0) {
          recordAssignment(varName, sources);
          if (Array.from(sources).some((s) => isTainted(s))) {
            taintedVars.add(varName);
          }
        }
      }
    }

    if (node.type === 'method_invocation') {
      const children = node.namedChildren;
      const methodIdent = children.find((c: any) =>
        c.type === 'identifier' && sqlExecutionMethods.includes(c.text)
      );
      const argList = children.find((c: any) => c.type === 'argument_list');

      if (methodIdent && argList) {
        const argVars = argList.namedChildren.filter((n: any) => n.type === 'identifier');
        const directTaint = argList.toString().split(/\W+/).some((t: any) => taintSources.includes(t));
        const tainted = argVars.some((v: any) => isTainted(v.text));
        const safeLiteralVars = argVars.every((v: any) => isSafeLiteralVariable(v.text));

        if ((directTaint || tainted) && !safeLiteralVars) {
          const { startPosition, endPosition } = node;
          findings.push({
            language: 'java',
            filePath: document.uri.fsPath,
            line: startPosition.row,
            column: startPosition.column,
            type: 'SQL_INJECTION',
            message: 'Possible SQL Injection: SQL executed with tainted input',
            codeSnippet: document.getText(new vscode.Range(
              startPosition.row, startPosition.column,
              endPosition.row, endPosition.column
            )),
          });
        }
      }
    }

    if (node.type === 'return_statement') {
      const expr = node.namedChildren[0];
      if (expr?.type === 'identifier' && isTainted(expr.text)) {
        findings.push({
          language: 'java',
          filePath: document.uri.fsPath,
          line: node.startPosition.row,
          column: node.startPosition.column,
          type: 'XSS',
          message: `Possible XSS: returning tainted string "${expr.text}"`,
          codeSnippet: document.getText(new vscode.Range(
            node.startPosition.row, node.startPosition.column,
            node.endPosition.row, node.endPosition.column
          )),
        });
      }
    }

    if (node.type === 'method_invocation') {
      const methodName = node.childForFieldName('name')?.text;
      const args = node.childForFieldName('arguments')?.namedChildren || [];
      const fullText = node.text;

      if ((methodName === 'write' || methodName === 'print' || methodName === 'println') && args.length) {
        const arg = args[0];
        if (arg?.type === 'identifier' && isTainted(arg.text)) {
          findings.push({
            language: 'java',
            filePath: document.uri.fsPath,
            line: node.startPosition.row,
            column: node.startPosition.column,
            type: 'XSS',
            message: `Possible XSS: response writer method '${methodName}' with tainted input`,
            codeSnippet: document.getText(new vscode.Range(
              node.startPosition.row, node.startPosition.column,
              node.endPosition.row, node.endPosition.column
            )),
          });
        }
      }
    }

    if (node.type === 'method_declaration') {
      const methodName = node.childForFieldName('name')?.text;
      const body = node.childForFieldName('body');
      const returnStmt = body?.namedChildren.find((c: any) => c.type === 'return_statement');
      const returnExpr = returnStmt?.namedChildren.find((n: any) => n.type === 'method_invocation');

      if (methodName && ['getParameter', 'getHeader'].includes(methodName) && returnExpr) {
        const taintSourceCall = returnExpr.namedChildren[1]?.text;
        if (taintSources.includes(taintSourceCall)) {
          findings.push({
            language: 'java',
            filePath: document.uri.fsPath,
            line: node.startPosition.row,
            column: node.startPosition.column,
            type: 'XSS',
            message: `Possible XSS: insecure wrapper overrides '${methodName}' returning tainted data`,
            codeSnippet: document.getText(new vscode.Range(
              node.startPosition.row, node.startPosition.column,
              node.endPosition.row, node.endPosition.column
            )),
          });
        }
      }
    }

    if (
      node.type === 'method_declaration' &&
      node.prevSibling?.type === 'modifiers' &&
      node.prevSibling?.text.includes('@WebMethod')
    ) {
      const body = node.childForFieldName('body');
      const returnStmt = body?.namedChildren.find((c: any) => c.type === 'return_statement');
      const expr = returnStmt?.namedChildren[0];
      if (expr?.type === 'identifier' && isTainted(expr.text)) {
        findings.push({
          language: 'java',
          filePath: document.uri.fsPath,
          line: node.startPosition.row,
          column: node.startPosition.column,
          type: 'XSS',
          message: `Possible XSS: @WebMethod endpoint returns tainted variable '${expr.text}'`,
          codeSnippet: document.getText(new vscode.Range(
            node.startPosition.row, node.startPosition.column,
            node.endPosition.row, node.endPosition.column
          )),
        });
      }
    }

    function collectIdentifiers(expr: any): string[] {
      const result: string[] = [];
      const visit = (n: any) => {
        if (n.type === 'identifier') {
          result.push(n.text);
        }
        if (n.namedChildren) {
          for (const child of n.namedChildren) {
            visit(child);
          }
        }
      };
      visit(expr);
      return result;
    }

    function isTaintedExpr(expr: any): boolean {
      if (expr.type === 'identifier') {
        return isTainted(expr.text);
      }
      return collectIdentifiers(expr).some(id => isTainted(id));
    }

    function hasClassAnnotation(classNode: any, annotation: string): boolean {
      const siblings = classNode.parent?.namedChildren || [];
      const index = siblings.indexOf(classNode);
      for (let i = index - 1; i >= 0; i--) {
        if (siblings[i].text.includes(annotation)) {
          return true;
        }
      }
      return false;
    }

    let inSpringControllerClass = false;
    if (node.type === 'class_declaration') {
      inSpringControllerClass = hasClassAnnotation(node, '@RestController') || hasClassAnnotation(node, '@Controller');
    }

    if (node.type === 'method_declaration') {
      const methodBody = node.childForFieldName('body');
      const returnStmt = methodBody?.namedChildren.find((c: any) => c.type === 'return_statement');
      const returnedExpr = returnStmt?.namedChildren[0];

      const hasSpringAnnotation =
        node.prevSibling?.type === 'modifiers' &&
        /@(?:GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|ResponseBody)/.test(node.prevSibling.text);

      const isSpringReturn = hasSpringAnnotation || inSpringControllerClass;

      if (returnedExpr && isSpringReturn && isTaintedExpr(returnedExpr)) {
        findings.push({
          language: 'java',
          filePath: document.uri.fsPath,
          line: node.startPosition.row,
          column: node.startPosition.column,
          type: 'XSS',
          message: `Possible XSS: Spring controller method returning tainted value`,
          codeSnippet: document.getText(new vscode.Range(
            node.startPosition.row, node.startPosition.column,
            node.endPosition.row, node.endPosition.column
          )),
        });
      }

      if (
        returnedExpr?.type === 'method_invocation' &&
        returnedExpr.text.includes('ResponseEntity.ok') &&
        isTaintedExpr(returnedExpr)
      ) {
        findings.push({
          language: 'java',
          filePath: document.uri.fsPath,
          line: node.startPosition.row,
          column: node.startPosition.column,
          type: 'XSS',
          message: `Possible XSS: ResponseEntity.ok() returning tainted input`,
          codeSnippet: document.getText(new vscode.Range(
            node.startPosition.row, node.startPosition.column,
            node.endPosition.row, node.endPosition.column
          )),
        });
      }
    }

    if (node.type === 'annotation' && node.text.startsWith('@Query') && node.text.includes('+')) {
      findings.push({
        language: 'java',
        filePath: document.uri.fsPath,
        line: node.startPosition.row,
        column: node.startPosition.column,
        type: 'SQL_INJECTION',
        message: 'Possible SQL Injection: JPA @Query annotation with concatenated input',
        codeSnippet: document.getText(new vscode.Range(
          node.startPosition.row, node.startPosition.column,
          node.endPosition.row, node.endPosition.column
        )),
      });
    }

    if (
      node.type === 'method_invocation' &&
      node.text.includes('createQuery') &&
      node.text.includes('+')
    ) {
      findings.push({
        language: 'java',
        filePath: document.uri.fsPath,
        line: node.startPosition.row,
        column: node.startPosition.column,
        type: 'SQL_INJECTION',
        message: 'Possible SQL Injection: createQuery with concatenated input',
        codeSnippet: document.getText(new vscode.Range(
          node.startPosition.row, node.startPosition.column,
          node.endPosition.row, node.endPosition.column
        )),
      });
    }

    if (
      node.type === 'method_invocation' &&
      node.text.match(/jdbcTemplate\.(query|update)/) &&
      node.text.includes('+')
    ) {
      findings.push({
        language: 'java',
        filePath: document.uri.fsPath,
        line: node.startPosition.row,
        column: node.startPosition.column,
        type: 'SQL_INJECTION',
        message: 'Possible SQL Injection: Spring JdbcTemplate with concatenated input',
        codeSnippet: document.getText(new vscode.Range(
          node.startPosition.row, node.startPosition.column,
          node.endPosition.row, node.endPosition.column
        )),
      });
    }

    if (
      node.type === 'method_invocation' &&
      node.text.startsWith('String.format') &&
      node.text.includes('+')
    ) {
      findings.push({
        language: 'java',
        filePath: document.uri.fsPath,
        line: node.startPosition.row,
        column: node.startPosition.column,
        type: 'SQL_INJECTION',
        message: 'Possible SQL Injection: String.format used with dynamic SQL parts',
        codeSnippet: document.getText(new vscode.Range(
          node.startPosition.row, node.startPosition.column,
          node.endPosition.row, node.endPosition.column
        )),
      });
    }

    if (
      node.type === 'method_invocation' &&
      node.text.includes('newQuery') &&
      node.text.includes('+')
    ) {
      findings.push({
        language: 'java',
        filePath: document.uri.fsPath,
        line: node.startPosition.row,
        column: node.startPosition.column,
        type: 'SQL_INJECTION',
        message: 'Possible SQL Injection: JDO newQuery with concatenated string',
        codeSnippet: document.getText(new vscode.Range(
          node.startPosition.row, node.startPosition.column,
          node.endPosition.row, node.endPosition.column
        )),
      });
    }

    if (node.type === 'local_variable_declaration') {
      const declarators = node.namedChildren.filter((c: any) => c.type === 'variable_declarator');
      for (const declarator of declarators) {
        const varName = declarator.namedChildren.find((c: any) => c.type === 'identifier')?.text;
        const valueNode = declarator.namedChildren.find((c: any) => c.type !== 'identifier');
        if (!varName || !valueNode) { continue; }

        if (valueNode.type === 'string_literal') {
          stringLiterals.add(varName);
          continue;
        }

        // check taint source
        if (
          valueNode.type === 'method_invocation' &&
          taintSources.includes(valueNode.namedChildren[1]?.text)
        ) {
          taintedVars.add(varName);
        }

        // check sanitization
        if (
          valueNode.type === 'method_invocation' &&
          valueNode.text &&
          sanitizers.some(s => valueNode.text.includes(s))
        ) {
          sanitizedVars.add(varName);
        }

        const sources = new Set<string>();
        const collectIdentifiers = (n: any) => {
          if (n.type === 'identifier') {
            sources.add(n.text);
          }
          for (const child of n.namedChildren || []) {
            collectIdentifiers(child);
          }
        };
        collectIdentifiers(valueNode);

        if (sources.size > 0) {
          recordAssignment(varName, sources);
          if (Array.from(sources).some((s) => isTainted(s))) {
            taintedVars.add(varName);
          }
        }
      }
    }

    for (const child of node.children || []) {
      visit(child);
    }

  };

  visit(rootNode);
  console.log('[sec-proj1] Total Findings:', findings.length);

  return findings;
}
