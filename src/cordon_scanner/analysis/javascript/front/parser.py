"""The syntax tree of a JavaScript or TypeScript source, by Cordon's own parser.

The second stage of the front end (`reviews/self-improving/08-JS-FRONT-END.md`). Recursive descent
for statements, precedence climbing for expressions, ESTree node types (`syntax.Node`).

What makes it safe to point at an attacker's file:

- It never backtracks over unbounded input. A parenthesised expression is parsed once and, when
  `=>` follows, reread as parameters (the cover grammar real engines use), so nested parentheses
  cannot make it quadratic. The one speculative parse, TypeScript type arguments (`f<T>(x)`), reads
  at most `LOOKAHEAD` tokens before falling back to `<` as less-than.
- Nesting is bounded. Past `MAX_DEPTH` levels a statement is given up as an `Error` node and
  parsing resumes after it: no input exhausts the interpreter's stack.
- It recovers. A statement it cannot read becomes an `Error` node spanning to the next statement
  boundary, and the rest of the file is still parsed. It never raises.

What it reads: ECMAScript 2024 (modules, classes with private and static members and static
blocks, destructuring with defaults, rest and spread, async functions and generators, optional
chaining, nullish coalescing and logical assignment, templates and tagged templates, `import()` and
`import.meta`, labelled statements, automatic semicolon insertion); TypeScript syntax (annotations,
generics, `as` and `satisfies`, non-null `!`, interfaces, type aliases, enums, namespaces,
`declare`, parameter properties, decorators, `import x = require(...)`), which has no runtime
effect and is passed over exactly; and JSX elements, whose attribute and child expressions are
parsed.
"""

from __future__ import annotations

from cordon_scanner.analysis.javascript.front.grammar.declarations import Declarations
from cordon_scanner.analysis.javascript.front.grammar.dialects import Dialects
from cordon_scanner.analysis.javascript.front.grammar.expressions import Expressions
from cordon_scanner.analysis.javascript.front.grammar.statements import Statements
from cordon_scanner.analysis.javascript.front.grammar.stream import ParseError


class Parser(Statements, Expressions, Declarations, Dialects):
    """`Parser(text, typescript=..., jsx=...).program()` gives the `Program` node, always."""


__all__ = ["ParseError", "Parser"]
