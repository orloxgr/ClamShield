// Source inspection for behavioral fixtures. TypeScript 7 no longer exports
// the old JavaScript compiler API; Babel parses source and esbuild strips types.
const { parse } = require('@babel/parser');
const { transformSync } = require('esbuild');
/** @returns {any} */
function createSourceFile(file, text, ..._options) {
  const parsed = parse(text, { sourceType: file.endsWith('.cjs') ? 'commonjs' : 'unambiguous', errorRecovery: true, plugins: ['typescript', ...(file.endsWith('.tsx') ? ['jsx'] : [])] });
  const unexpected = parsed.errors.filter(error => !['VarRedeclaration', 'DuplicateExport'].includes(error.reasonCode));
  if (unexpected.length) throw unexpected[0];
  const visited = new WeakSet();
  function decorate(node) {
    if (!node || typeof node !== 'object' || typeof node.type !== 'string') return;
    if (visited.has(node)) return;
    visited.add(node);
    const children = Object.entries(node).filter(([key]) => !['loc', 'comments', 'tokens', 'errors'].includes(key))
      .flatMap(([, value]) => Array.isArray(value) ? value : [value]).filter(value => value && typeof value === 'object' && typeof value.type === 'string');
    children.forEach(decorate);
    Object.defineProperty(node, '_children', { value: children });
    node.getText = () => text.slice(node.start, node.end);
    if (node.type === 'Identifier') node.text = node.name;
    if (['StringLiteral', 'JSXText'].includes(node.type)) node.text = node.value;
    if (node.type === 'CallExpression') node.expression = node.callee;
    if (node.type === 'MemberExpression') { node.expression = node.object; node.name = node.property; }
    if (node.type === 'FunctionDeclaration') node.name = node.id;
  }
  decorate(parsed.program);
  parsed.program.statements = parsed.program.body.map(node => node.type === 'ExportNamedDeclaration' && node.declaration ? node.declaration : node);
  return parsed.program;
}
function transpile(code, options = {}) {
  return transformSync(code, { loader: 'ts', target: 'es2022', ...(options.module === 'commonjs' ? { format: 'cjs' } : {}) }).code;
}
module.exports = {
  createSourceFile, transpile, transpileModule: (code, options = {}) => ({ outputText: transpile(code, options.compilerOptions) }),
  forEachChild: (node, visit) => { for (const child of node._children || []) visit(child); },
  isFunctionDeclaration: node => node?.type === 'FunctionDeclaration',
  isCallExpression: node => node?.type === 'CallExpression',
  isStringLiteral: node => node?.type === 'StringLiteral',
  isJsxText: node => node?.type === 'JSXText',
  isExpressionStatement: node => node?.type === 'ExpressionStatement',
  isPropertyAccessExpression: node => node?.type === 'MemberExpression',
  ScriptTarget: { Latest: 'latest', ES2022: 'es2022' }, ScriptKind: { TS: 'ts', TSX: 'tsx', JS: 'js' }, ModuleKind: { None: 'none', CommonJS: 'commonjs' }
};
