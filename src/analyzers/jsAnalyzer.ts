import * as vscode from 'vscode';
import { getParser } from './utils/treeSitterLoader';
import { VulnerabilityFinding } from '../types';

export async function analyzeJavaScript(document: vscode.TextDocument): Promise<VulnerabilityFinding[]> {
    const parser = getParser('javascript');
    const tree = parser.parse(document.getText());

    const findings: VulnerabilityFinding[] = [];
    const rootNode = tree.rootNode;

    const taintedVars = new Set<string>();
    const varAssignments = new Map<string, Set<string>>();

    console.log('[sec-proj1] Running JS analysis');
    console.log('[sec-proj1] AST:\n', rootNode.toString());

    function recordAssignment(target: string, sources: Set<string>) {
        if (!varAssignments.has(target)) {
            varAssignments.set(target, new Set());
        }
        sources.forEach((s) => varAssignments.get(target)!.add(s));
    }

    function isTainted(varName: string, visited = new Set<string>()): boolean {
        if (taintedVars.has(varName)) { return true; }
        if (visited.has(varName)) { return false; }
        visited.add(varName);

        const deps = varAssignments.get(varName);
        if (!deps) { return false; }

        return Array.from(deps).some((d) => isTainted(d, visited));
    }

    function getMemberChain(node: any): string[] {
        const chain: string[] = [];

        function visit(n: any) {
            if (!n) { return; }

            if (n.type === 'member_expression') {
                const property = n.childForFieldName('property');
                if (property) {
                    chain.unshift(property.text);
                }
                visit(n.childForFieldName('object'));
            } else if (n.type === 'call_expression') {
                visit(n.childForFieldName('function'));
            } else if (n.type === 'identifier') {
                chain.unshift(n.text);
            }
        }

        visit(node);
        return chain;
    }


    function isTaintedSourceMember(node: any): boolean {
        const chain = getMemberChain(node);
        if (chain.length < 2) { return false; }
        const [base, firstProp] = chain;
        const isTainted = base === 'req' && ['query', 'body', 'params'].includes(firstProp);
        if (isTainted) {
        }
        return isTainted;
    }

    function containsTaintedIdentifier(node: any): boolean {
        const idents = new Set<string>();
        collectIdentifiers(node, idents);
        return Array.from(idents).some((v) => isTainted(v, new Set()));

    }

    function isDOMTainted(node: any): boolean {
        const chain = getMemberChain(node);
        const sources = [
            ['document', 'getElementById'],
            ['document', 'querySelector'],
            ['document', 'forms'],
            ['location', 'search'],
            ['location', 'hash'],
            ['location', 'href']
        ];

        for (const src of sources) {
            if (src.every((v, i) => chain[i] === v)) {
                return true;
            }
        }

        if ((chain[0] === 'document') &&
            (chain[1] === 'getElementById' || chain[1] === 'querySelector') &&
            chain.includes('value')) {
            return true;
        }
        return false;
    }

    function isDOMTaintedSource(node: any): boolean {
        const chain = getMemberChain(node);
        if (chain.length >= 3 && chain[0] === 'document') {
            if (
                (chain[1] === 'getElementById' || chain[1] === 'querySelector') &&
                chain.includes('value')
            ) {
                return true;
            }
        }
        return false;
    }

    function collectIdentifiers(node: any, result: Set<string>) {
        if (!node) { return; }
        if (node.type === 'identifier') {
            result.add(node.text);
        }
        for (const child of node.namedChildren || []) {
            collectIdentifiers(child, result);
        }
    }

    function containsTaintedTemplate(node: any): boolean {
        if (node.type !== 'template_string') { return false; }
        const embedded = node.namedChildren.filter((c: any) => c.type === 'template_substitution');
        return embedded.some((sub: any) => containsTaintedIdentifier(sub));
    }

    function containsTaintedBinary(node: any): boolean {
        if (node.type !== 'binary_expression') { return false; }

        const left = node.child(0);
        const right = node.child(2);

        return containsTaintedIdentifier(left) || containsTaintedIdentifier(right);
    }

    const visit = (node: any) => {
        if (node.type === 'variable_declaration') {
            for (const declarator of node.namedChildren) {
                if (declarator.type !== 'variable_declarator') { continue; }
                const varName = declarator.namedChildren.find((c: any) => c.type === 'identifier')?.text;
                const valueNode = declarator.namedChildren.find((c: any) => c.type !== 'identifier');
                if (!varName || !valueNode) { continue; }

                if (isTaintedSourceMember(valueNode || isDOMTainted(valueNode))) {
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

        if (node.type === 'assignment_expression') {
            const left = node.namedChildren[0];
            const right = node.namedChildren[1];
            const property = left?.childForFieldName('property');

            if (property?.text === 'innerHTML') {
                if (right.type === 'identifier' && isTainted(right.text)) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'XSS',
                        message: `Possible XSS: innerHTML set with tainted variable "${right.text}"`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const argsNode = node.childForFieldName('arguments');
            const args = argsNode?.namedChildren;

            if (func?.text?.endsWith('.setAttribute') && args?.length === 2) {
                const [attrName, attrValue] = args;
                if (attrName.type === 'string' && attrName.text.includes('src')) {
                    if (attrValue.type === 'identifier' && isTainted(attrValue.text)) {
                        findings.push({
                            language: 'javascript',
                            filePath: document.uri.fsPath,
                            line: node.startPosition.row,
                            column: node.startPosition.column,
                            type: 'XSS',
                            message: `Possible XSS: setAttribute("src", ...) with tainted input`,
                            codeSnippet: document.getText(new vscode.Range(
                                node.startPosition.row, node.startPosition.column,
                                node.endPosition.row, node.endPosition.column
                            )),
                        });
                    }
                }
            }
        }

        if (
            node.type === 'call_expression' &&
            node.childForFieldName('function')?.text?.match(/^res\.(send|write)$/)
        ) {
            const args = node.childForFieldName('arguments')?.namedChildren || [];
            const arg = args[0];

            if (!arg) { return; }

            const isHTMLLike = (text: string) => /<\/?[a-z]/i.test(text);
            const isTemplateString = arg.type === 'template_string';
            const isBinaryConcat = arg.type === 'binary_expression';

            const hasHTMLPattern =
                (isTemplateString && isHTMLLike(arg.text)) ||
                (isBinaryConcat && isHTMLLike(arg.text));

            const tainted = containsTaintedIdentifier(arg);

            if (hasHTMLPattern && tainted) {
                findings.push({
                    language: 'javascript',
                    filePath: document.uri.fsPath,
                    line: node.startPosition.row,
                    column: node.startPosition.column,
                    type: 'XSS',
                    message: 'Possible XSS: HTML response with embedded tainted input',
                    codeSnippet: document.getText(new vscode.Range(
                        node.startPosition.row, node.startPosition.column,
                        node.endPosition.row, node.endPosition.column
                    )),
                });
            }
        }

        if (node.type === 'variable_declarator') {
            const varName = node.childForFieldName('name')?.text;
            const valueNode = node.childForFieldName('value');

            if (varName && valueNode && isTaintedSourceMember(valueNode)) {
                taintedVars.add(varName);
            }

            if (varName && valueNode && isDOMTaintedSource(valueNode)) {
                taintedVars.add(varName);
            }

            const sources = new Set<string>();
            collectIdentifiers(valueNode, sources);
            if (sources.size) {
                recordAssignment(varName, sources);
                if (Array.from(sources).some(s => isTainted(s))) {
                    taintedVars.add(varName);
                }
            }
        }

        if (node.type === 'call_expression') {
            const callee = node.namedChildren[0];  // db.query
            const args = node.namedChildren.find((c: any) => c.type === 'arguments')?.namedChildren || [];

            if (
                callee?.type === 'member_expression' &&
                callee?.namedChildren?.[1]?.type === 'property_identifier' &&
                callee?.namedChildren?.[1]?.text === 'query'
            ) {
                const arg0 = args[0];
                if (arg0?.type === 'identifier' && isTainted(arg0.text)) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'SQL_INJECTION',
                        message: `Possible SQL Injection: db.query(...) with tainted input "${arg0.text}"`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            if (func?.type === 'member_expression') {
                const methodName = func.childForFieldName('property')?.text;

                if (
                    ['insertAdjacentHTML', 'insertBefore', 'setHTML'].includes(methodName)
                ) {
                    for (const arg of args) {
                        if (
                            arg.type === 'identifier' && isTainted(arg.text) ||
                            containsTaintedIdentifier(arg)
                        ) {
                            findings.push({
                                language: 'javascript',
                                filePath: document.uri.fsPath,
                                line: node.startPosition.row,
                                column: node.startPosition.column,
                                type: 'XSS',
                                message: `Possible XSS: ${methodName} called with tainted input`,
                                codeSnippet: document.getText(new vscode.Range(
                                    node.startPosition.row, node.startPosition.column,
                                    node.endPosition.row, node.endPosition.column
                                )),
                            });
                            break;
                        }
                    }
                }
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            if (func?.type === 'member_expression') {
                const object = func.childForFieldName('object');
                const method = func.childForFieldName('property');

                if (
                    object?.text === 'document' &&
                    ['write', 'writeln'].includes(method?.text)
                ) {
                    for (const arg of args) {
                        if (
                            arg.type === 'identifier' && isTainted(arg.text) ||
                            containsTaintedIdentifier(arg)
                        ) {
                            findings.push({
                                language: 'javascript',
                                filePath: document.uri.fsPath,
                                line: node.startPosition.row,
                                column: node.startPosition.column,
                                type: 'XSS',
                                message: `Possible XSS: document.${method.text} called with tainted input`,
                                codeSnippet: document.getText(new vscode.Range(
                                    node.startPosition.row, node.startPosition.column,
                                    node.endPosition.row, node.endPosition.column
                                )),
                            });
                            break;
                        }
                    }
                }
            }
        }

        if (node.type === 'binary_expression') {
            const left = node.namedChildren?.[0];
            const right = node.namedChildren?.[1];

            const isStr = (n: any) => ['string', 'template_string'].includes(n?.type);
            const isTaintedId = (n: any) => n?.type === 'identifier' && isTainted(n.text);

            const isConcatOfStringAndTainted =
                (isStr(left) && isTaintedId(right)) ||
                (isTaintedId(left) && isStr(right)) ||
                (isTaintedId(left) && isTaintedId(right));  // optional: both tainted

            if (isConcatOfStringAndTainted) {
                findings.push({
                    language: 'javascript',
                    filePath: document.uri.fsPath,
                    line: node.startPosition.row,
                    column: node.startPosition.column,
                    type: 'XSS',
                    message: `Possible XSS: HTML string built using tainted input via concatenation`,
                    codeSnippet: document.getText(new vscode.Range(
                        node.startPosition.row, node.startPosition.column,
                        node.endPosition.row, node.endPosition.column
                    )),
                });
            }
        }

        if (node.type === 'call_expression') {
            const funcText = node.childForFieldName('function')?.text;
            const args = node.childForFieldName('arguments')?.namedChildren;

            if (funcText?.endsWith('.html') && args?.length === 1) {
                const arg = args[0];
                if (arg.type === 'identifier' && isTainted(arg.text)) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'XSS',
                        message: `Possible XSS: jQuery .html(...) with tainted input`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren;
            if (func?.text?.endsWith('.send') || func?.text?.endsWith('.write')) {
                const [arg] = args || [];
                if (arg?.type === 'template_string') {
                    const embeddedExprs = arg.namedChildren.filter((c: any) => c.type === 'template_substitution');
                    const taintedExprs = embeddedExprs.filter((sub: any) => containsTaintedIdentifier(sub));

                    if (taintedExprs.length > 0) {
                        findings.push({
                            language: 'javascript',
                            filePath: document.uri.fsPath,
                            line: node.startPosition.row,
                            column: node.startPosition.column,
                            type: 'XSS',
                            message: `Possible XSS: HTML response with tainted template substitution`,
                            codeSnippet: document.getText(new vscode.Range(
                                node.startPosition.row, node.startPosition.column,
                                node.endPosition.row, node.endPosition.column
                            )),
                        });
                    }
                }
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren;

            const isEvalLike =
                func?.text === 'setTimeout' ||
                func?.text === 'setInterval' ||
                func?.text === 'Function' ||
                (func?.type === 'new_expression' && func?.namedChildren?.[0]?.text === 'Function');

            if (isEvalLike && args?.length) {
                const firstArg = args[0];

                const isDangerousString =
                    firstArg.type === 'string' ||
                    (firstArg.type === 'template_string' &&
                        firstArg.namedChildren.some((c: any) =>
                            c.type === 'template_substitution' &&
                            c.namedChildren.some((n: any) =>
                                n.type === 'identifier' && isTainted(n.text)
                            )
                        ));

                const isTaintedVar = firstArg.type === 'identifier' && isTainted(firstArg.text);

                if (isDangerousString || isTaintedVar) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'XSS',
                        message: `Possible XSS: usage of ${func.text} with tainted or dynamic code`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const callee = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            const isQueryFunction = callee?.text?.match(/\b(query|execute|run)\b/);

            if (isQueryFunction && args.length > 0) {
                const firstArg = args[0];

                if (firstArg.type === 'template_string') {
                    const embeddedExprs = firstArg.namedChildren.filter((c: any) => c.type === 'template_substitution');

                    const taintedExprs = embeddedExprs.filter((sub: any) => {
                        const id = sub.namedChildren.find((n: any) => n.type === 'identifier');
                        return id && isTainted(id.text);
                    });

                    if (taintedExprs.length > 0) {
                        findings.push({
                            language: 'javascript',
                            filePath: document.uri.fsPath,
                            line: node.startPosition.row,
                            column: node.startPosition.column,
                            type: 'SQL_INJECTION',
                            message: `Possible SQL Injection: SQL template string with tainted input`,
                            codeSnippet: document.getText(new vscode.Range(
                                node.startPosition.row, node.startPosition.column,
                                node.endPosition.row, node.endPosition.column
                            )),
                        });
                    }
                }
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            if (
                func?.type === 'member_expression' &&
                (func.text.includes('sequelize.query') || func.text.includes('db.query'))
            ) {
                const arg = args[0];

                const isTaintedArg =
                    (arg?.type === 'identifier' && isTainted(arg.text)) ||
                    (arg?.type === 'template_string' && containsTaintedTemplate(arg)) ||
                    (arg?.type === 'binary_expression' && containsTaintedBinary(arg));

                if (isTaintedArg) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'SQL_INJECTION',
                        message: 'Possible SQL Injection: sequelize.query with tainted input',
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const callee = node.childForFieldName('function');
            const args = node.childForFieldName('arguments');

            if (callee && callee.type === 'member_expression') {
                const object = callee.childForFieldName('object');
                const property = callee.childForFieldName('property');

                if (object?.text === 'knex' && property?.text === 'raw' && args) {
                    const argNode = args.namedChildren[0];

                    const isConcat = argNode?.type === 'binary_expression' && argNode.operator === '+';
                    const isTemplate = argNode?.type === 'template_string';
                    const containsTaint = containsTaintedIdentifier(argNode);
                    const isDOMSource = isDOMTainted(argNode);

                    if ((isConcat || isTemplate) && (containsTaint || isDOMSource)) {
                        findings.push({
                            language: 'javascript',
                            filePath: document.uri.fsPath,
                            line: node.startPosition.row,
                            column: node.startPosition.column,
                            type: 'SQL_INJECTION',
                            message: 'Possible SQL Injection: knex.raw() used with dynamic input',
                            codeSnippet: document.getText(new vscode.Range(
                                node.startPosition.row, node.startPosition.column,
                                node.endPosition.row, node.endPosition.column
                            )),
                        });
                    }
                }
            }
        }

        if (node.type === 'call_expression') {
            const callee = node.childForFieldName('function');
            const args = node.childForFieldName('arguments');

            const memberChain = getMemberChain(callee);
            const isTypeORMQueryCall = memberChain.length >= 2 && memberChain[1] === 'query';

            if (isTypeORMQueryCall && args) {
                const arg0 = args.namedChildren?.[0];
                const isArgTainted =
                    isTaintedSourceMember(arg0) ||
                    isDOMTainted(arg0) ||
                    containsTaintedIdentifier(arg0);

                if (isArgTainted) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'SQL_INJECTION',
                        message: `Possible SQL Injection: TypeORM query() called with tainted input`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const callee = node.childForFieldName('function');
            const args = node.childForFieldName('arguments');

            const memberChain = getMemberChain(callee);

            const isBuilderWhereCall =
                memberChain.length >= 2 &&
                memberChain.includes('createQueryBuilder') &&
                memberChain.includes('where');

            if (isBuilderWhereCall && args) {
                const arg0 = args.namedChildren?.[0];

                const isArgTainted =
                    isTaintedSourceMember(arg0) ||
                    isDOMTainted(arg0) ||
                    containsTaintedIdentifier(arg0);

                if (isArgTainted) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'SQL_INJECTION',
                        message: `Possible SQL Injection: TypeORM QueryBuilder where() with tainted input`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const callee = node.childForFieldName('function');
            const args = node.childForFieldName('arguments');

            const memberChain = getMemberChain(callee);

            const isPrismaRawCall =
                memberChain.length >= 2 &&
                memberChain[0] === 'prisma' &&
                memberChain[1] === '$queryRaw';

            if (isPrismaRawCall && args?.namedChildren?.length > 0) {
                const arg0 = args.namedChildren[0];

                const isArgTainted =
                    isTaintedSourceMember(arg0) ||
                    isDOMTainted(arg0) ||
                    containsTaintedIdentifier(arg0);

                if (isArgTainted) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'SQL_INJECTION',
                        message: `Possible SQL Injection: prisma.$queryRaw() with tainted input`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const callee = node.childForFieldName('function');
            const args = node.childForFieldName('arguments');
            const memberChain = getMemberChain(callee);

            const isMikroORMQueryBuilderCall =
                memberChain.length >= 3 &&
                memberChain.includes('createQueryBuilder') &&
                memberChain.includes('where');

            if (isMikroORMQueryBuilderCall && args?.namedChildren?.length > 0) {
                const arg0 = args.namedChildren[0];

                const isArgTainted =
                    isTaintedSourceMember(arg0) ||
                    isDOMTainted(arg0) ||
                    containsTaintedIdentifier(arg0);

                if (isArgTainted) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'SQL_INJECTION',
                        message: `Possible SQL Injection: MikroORM createQueryBuilder().where(...) with tainted input`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            args.forEach((argNode: any, idx: number) => {
                if (
                    isTaintedSourceMember(argNode) ||
                    isDOMTainted(argNode) ||
                    containsTaintedIdentifier(argNode)
                ) {
                    const func = node.childForFieldName('function');
                    if (func && func.type === 'identifier') {
                        const taintLabel = `${func.text}_param${idx}`;
                        taintedVars.add(taintLabel);
                    }
                }
            });
        }

        if (node.type === 'function_declaration' || node.type === 'function') {
            const funcName = node.childForFieldName('name')?.text;
            const params = node.childForFieldName('parameters')?.namedChildren || [];
            const body = node.childForFieldName('body');

            params.forEach((paramNode: any, idx: number) => {
                const paramName = paramNode.text;
                const taintLabel = `${funcName}_param${idx}`;
                if (taintedVars.has(taintLabel)) {
                    taintedVars.add(paramName);
                }
            });
        }

        if (
            node.type === 'jsx_attribute' &&
            node.name?.text === 'dangerouslySetInnerHTML'
        ) {
            const valueNode = node.value?.expression;
            if (
                valueNode &&
                valueNode.type === 'object' &&
                valueNode.properties
            ) {
                const htmlProp = valueNode.properties.find(
                    (p: any) =>
                        p.key?.name === '__html' &&
                        p.value?.type === 'Identifier' &&
                        isTainted(p.value.name)
                );

                if (htmlProp) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.loc.start.line - 1,
                        column: node.loc.start.column,
                        type: 'XSS',
                        message: `Possible XSS: dangerouslySetInnerHTML with tainted value "${htmlProp.value.name}"`,
                        codeSnippet: document.getText(new vscode.Range(
                            new vscode.Position(node.loc.start.line - 1, node.loc.start.column),
                            new vscode.Position(node.loc.end.line - 1, node.loc.end.column)
                        )),
                    });
                }
            }
        }

        if (
            node.type === 'assignment_expression' &&
            node.left?.type === 'member_expression'
        ) {
            const chain = getMemberChain(node.left);
            if (
                chain.length >= 3 &&
                chain[1] === 'current' &&
                (chain[2] === 'innerHTML' || chain[2] === 'outerHTML')
            ) {
                const right = node.right;
                if (right?.type === 'identifier' && isTainted(right.name)) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.loc.start.line - 1,
                        column: node.loc.start.column,
                        type: 'XSS',
                        message: `Possible XSS: assignment to ${chain.join('.')} with tainted value "${right.name}"`,
                        codeSnippet: document.getText(new vscode.Range(
                            new vscode.Position(node.loc.start.line - 1, node.loc.start.column),
                            new vscode.Position(node.loc.end.line - 1, node.loc.end.column)
                        )),
                    });
                }
            }
        }

        if (node.type === 'binary_expression' && node.operator === '+') {
            const left = node.child(0);
            const right = node.child(1);

            const isHTMLLike = (n: any) =>
                n.type === 'string' && /<\/?[a-z]/i.test(n.text);

            const hasHTML = isHTMLLike(left) || isHTMLLike(right);
            const tainted = containsTaintedIdentifier(left) || containsTaintedIdentifier(right);

            if (hasHTML && tainted) {
                findings.push({
                    language: 'javascript',
                    filePath: document.uri.fsPath,
                    line: node.startPosition.row,
                    column: node.startPosition.column,
                    type: 'XSS',
                    message: 'Possible XSS: HTML string built via concatenation with tainted input',
                    codeSnippet: document.getText(new vscode.Range(
                        node.startPosition.row, node.startPosition.column,
                        node.endPosition.row, node.endPosition.column
                    )),
                });
            }
        }

        if (node.type === 'return_statement') {
            const obj = node.namedChildren[0];
            if (obj?.type === 'object') {
                const bodyProp = obj.namedChildren.find((c: any) =>
                    c.type === 'pair' &&
                    c.namedChildren[0]?.text === 'body'
                );

                if (bodyProp) {
                    const valueNode = bodyProp.namedChildren[1];
                    const containsTainted =
                        (valueNode.type === 'template_string' || valueNode.type === 'binary_expression') &&
                        containsTaintedIdentifier(valueNode);

                    if (containsTainted) {
                        findings.push({
                            language: 'javascript',
                            filePath: document.uri.fsPath,
                            line: node.startPosition.row,
                            column: node.startPosition.column,
                            type: 'XSS',
                            message: `Possible XSS: Lambda response body contains tainted input`,
                            codeSnippet: document.getText(new vscode.Range(
                                node.startPosition.row, node.startPosition.column,
                                node.endPosition.row, node.endPosition.column
                            )),
                        });
                    }
                }
            }
        }

        if (node.type === 'assignment_expression') {
            const left = node.childForFieldName('left');
            const right = node.childForFieldName('right');

            const memberChain = getMemberChain(left);
            const isInnerOrOuterHTML =
                memberChain.slice(-2).includes('innerHTML') || memberChain.slice(-2).includes('outerHTML');
            const containsNativeElement = memberChain.includes('nativeElement');

            if (isInnerOrOuterHTML && containsNativeElement && containsTaintedIdentifier(right)) {
                findings.push({
                    language: 'javascript',
                    filePath: document.uri.fsPath,
                    line: node.startPosition.row,
                    column: node.startPosition.column,
                    type: 'XSS',
                    message: `Possible XSS: Angular ElementRef.nativeElement.${memberChain.at(-1)} assignment with tainted input`,
                    codeSnippet: document.getText(new vscode.Range(
                        node.startPosition.row, node.startPosition.column,
                        node.endPosition.row, node.endPosition.column
                    )),
                });
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            const isBypassTrustHtml = func?.text?.includes('bypassSecurityTrustHtml');

            if (isBypassTrustHtml && args.length && containsTaintedIdentifier(args[0])) {
                findings.push({
                    language: 'javascript',
                    filePath: document.uri.fsPath,
                    line: node.startPosition.row,
                    column: node.startPosition.column,
                    type: 'XSS',
                    message: `Possible XSS: bypassSecurityTrustHtml(...) called with tainted input`,
                    codeSnippet: document.getText(new vscode.Range(
                        node.startPosition.row, node.startPosition.column,
                        node.endPosition.row, node.endPosition.column
                    )),
                });
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            const isSceDisabled =
                func?.text === '$sceProvider.enabled' &&
                args.length &&
                args[0].type === 'false';

            if (isSceDisabled) {
                findings.push({
                    language: 'javascript',
                    filePath: document.uri.fsPath,
                    line: node.startPosition.row,
                    column: node.startPosition.column,
                    type: 'XSS',
                    message: `Possible XSS: \$sceProvider.enabled(false) disables Angular SCE`,
                    codeSnippet: document.getText(new vscode.Range(
                        node.startPosition.row, node.startPosition.column,
                        node.endPosition.row, node.endPosition.column
                    )),
                });
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            const funcName = func?.text || '';
            const isTrustAsCall =
                funcName.startsWith('$sce.trustAs') && args.length;

            if (isTrustAsCall) {
                const taintedArg = args.find((arg: any) =>
                    arg.type === 'identifier' && isTainted(arg.text)
                );

                if (taintedArg) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'XSS',
                        message: `Possible XSS: \$sce trustAs method used with tainted input`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'call_expression') {
            const func = node.childForFieldName('function');
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            const funcName = func?.text;
            const riskyFns = ['setTimeout', 'setInterval'];

            if (riskyFns.includes(funcName) && args.length > 0) {
                const arg = args[0];
                if (arg.type === 'identifier' && isTainted(arg.text)) {
                    findings.push({
                        language: 'javascript',
                        filePath: document.uri.fsPath,
                        line: node.startPosition.row,
                        column: node.startPosition.column,
                        type: 'XSS',
                        message: `Possible XSS: ${funcName} called with tainted input`,
                        codeSnippet: document.getText(new vscode.Range(
                            node.startPosition.row, node.startPosition.column,
                            node.endPosition.row, node.endPosition.column
                        )),
                    });
                }
            }
        }

        if (node.type === 'new_expression') {
            const ctor = node.childForFieldName('constructor');
            const args = node.childForFieldName('arguments')?.namedChildren || [];

            if (ctor?.text === 'Function') {
                for (const arg of args) {
                    if (arg.type === 'identifier' && isTainted(arg.text)) {
                        findings.push({
                            language: 'javascript',
                            filePath: document.uri.fsPath,
                            line: node.startPosition.row,
                            column: node.startPosition.column,
                            type: 'XSS',
                            message: `Possible XSS: Function constructor called with tainted input`,
                            codeSnippet: document.getText(new vscode.Range(
                                node.startPosition.row, node.startPosition.column,
                                node.endPosition.row, node.endPosition.column
                            )),
                        });
                    }
                }
            }
        }

        if (node.type === 'assignment_expression') {
            const left = node.childForFieldName('left');
            const right = node.childForFieldName('right');

            if (left?.type === 'member_expression') {
                const property = left.childForFieldName('property');
                const object = left.childForFieldName('object');

                if (property?.text === 'src' && object?.text === 'script') {
                    if (right?.type === 'identifier' && isTainted(right.text)) {
                        findings.push({
                            language: 'javascript',
                            filePath: document.uri.fsPath,
                            line: node.startPosition.row,
                            column: node.startPosition.column,
                            type: 'XSS',
                            message: 'Possible XSS: script.src assigned with tainted input',
                            codeSnippet: document.getText(new vscode.Range(
                                node.startPosition.row, node.startPosition.column,
                                node.endPosition.row, node.endPosition.column
                            )),
                        });
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
