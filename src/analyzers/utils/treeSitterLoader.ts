import Parser from 'tree-sitter';
import Java from 'tree-sitter-java';
import JavaScript from 'tree-sitter-javascript';

const parsers: { [lang: string]: Parser } = {};

export function getParser(language: string): Parser {
    if (parsers[language]) {
        return parsers[language];
    }

    const parser = new Parser();
    switch (language) {
        case 'java':
            parser.setLanguage(Java);
            break;
        case 'javascript':
            parser.setLanguage(JavaScript);
            break;
        default:
            throw new Error(`Unsupported language: ${language}`);
    }

    parsers[language] = parser;
    return parser;
}