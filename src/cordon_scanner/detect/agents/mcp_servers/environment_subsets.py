"""What a comprehension over the environment keeps, and where the subset goes: a scrub is not a
collector, and a subset that only becomes a child process's environment is not harvested.

`McpCode.secret_harvest` finds a comprehension over the environment whose conditions hold a
secret-like word and whose kept value is not a constant. That predicate reads neither the polarity
of the condition nor the use of the result, so two ordinary things match it: an environment
filter that DROPS the secret-named variables (`if not k.endswith("_TOKEN")`, `if k not in
SECRET_NAMES`), and the subset a server hands to a process it launches (`subprocess.run(cmd,
env=subset)`). Neither gathers a secret anywhere; both are what a server does to keep a secret out
of, or pass it only to, a child it started.

```
  {k: v for k, v in os.environ.items() if <test holding a secret word>}
        │
        ├─ R1  every secret-bearing test is a NEGATED top-level conjunct, one of them plain
        │        not k.endswith(..)  not any(w in k ..)  "w" not in k  not re.search(.., k)
        │        k not in SECRET_NAMES (a denylist)      + `k != name`, `k not in names` beside it
        │      not a scrub: under an `or`, around a `find(..) < 0`, around a length or a
        │      `a or b`, doubled, `k != name` alone, or beside a positive secret test
        │
        └─ where the subset goes (a plain name, `X.update(..)`, `X[..] = ..`, up to three hops)
             env= of a launched process / os.environ.update(..) / never read   -> local (R2)
             returned, yielded                                                  -> a scrub may
             sent, written, logged, printed, serialised                         -> still matched
                                                                                   even a scrub's
             anything else, or not followed                                     -> still matched
                                                                                   unless a scrub

  clears = (a scrub AND no visible sink)  OR  (every flow is local)
```

A scrub that leaves through a visible sink keeps matching: a near-whole environment sent, written,
logged or serialised is what the rule caught before, and it is not dropped without proof that
another rule catches it.

Read from the syntax tree; nothing is imported or run. Where this module cannot prove a
comprehension harmless it says nothing, and the rule's finding stands.
"""

from __future__ import annotations

import ast
import re
from typing import ClassVar

_Comprehension = ast.DictComp | ast.ListComp | ast.SetComp | ast.GeneratorExp


class EnvironmentSubsets:
    """Whether a flagged comprehension is a scrub, or a subset that stays inside the process tree.
    Stateless."""

    #: Calls that start a process; the subset is harmless there only as `env=`.
    LAUNCHES: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|\.)(?:Popen|run|call|check_call|check_output|create_subprocess_exec|"
        r"create_subprocess_shell|execve|execvpe|spawnve|spawnvpe|StdioServerParameters)$"
    )
    #: Writes into the process's own environment: a restore, an update, a default.
    ENVIRONMENT_WRITES: ClassVar[frozenset[str]] = frozenset(
        {"os.environ.update", "environ.update", "os.environ.setdefault", "environ.setdefault"}
    )
    #: Copies keep the subset's meaning; the copy is followed instead.
    COPIES: ClassVar[frozenset[str]] = frozenset({"dict", "copy.copy", "copy.deepcopy"})
    #: Flows that keep the subset inside the process tree.
    LOCAL: ClassVar[frozenset[str]] = frozenset({"CHILD_ENV", "ENVIRONMENT_WRITE", "UNUSED"})
    #: Flows through which the subset leaves where anyone can see it.
    VISIBLE: ClassVar[frozenset[str]] = frozenset(
        {"SENT", "WRITTEN", "LOGGED", "PRINTED", "SERIALISED"}
    )
    _SENDS: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)requests|httpx|urllib|aiohttp|socket|http\.client|urlopen|\.post$|\.put$|\.send|"
        r"\.request$|webhook|smtplib|ftplib"
    )
    _LOGS: ClassVar[re.Pattern[str]] = re.compile(
        r"(?i)(?:^|\.)(?:debug|info|warning|warn|error|exception|critical|log)$|logging|logger"
    )
    _WRITES: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|\.)(?:write|writelines|write_text|write_bytes|writerow|writerows)$"
    )
    _SERIALISES: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:^|\.)(?:dumps|dump|safe_dump|serialize|encode|b64encode|urlencode|pformat|repr|str|"
        r"format)$"
    )
    _REGEX_CALLS: ClassVar[frozenset[str]] = frozenset({"re.search", "re.match", "re.fullmatch"})
    _MAX_HOPS: ClassVar[int] = 3

    @classmethod
    def clears(cls, tree: ast.AST, node: _Comprehension, secret_words: re.Pattern[str]) -> bool:
        """Whether a flagged comprehension is not a harvest: it is a scrub whose result does not
        leave through a visible sink, or its subset only becomes a launched process's environment,
        is written back into `os.environ`, or is never read."""
        flows = cls.flows(tree, node)
        if cls.is_scrub(node, secret_words) and not flows & cls.VISIBLE:
            return True
        return bool(flows) and flows <= cls.LOCAL

    # ------------------------------------------------------------------ R1: a scrub

    @classmethod
    def is_scrub(cls, node: _Comprehension, secret_words: re.Pattern[str]) -> bool:
        """Whether the comprehension drops the secret-named variables and keeps the rest: one
        secret-bearing conjunct is a plain negation, and every other is a plain negation or an
        exact-name one (`k != name`, `k not in names`), which can only drop more. A secret word
        under an `or`, in a positive test, or in a negation that is not plain keeps it a collector;
        names alone, with no plain negation, drop only the names listed."""
        keys = {
            name.id
            for generator in node.generators
            for name in ast.walk(generator.target)
            if isinstance(name, ast.Name)
        }
        tests = [
            test
            for generator in node.generators
            for condition in generator.ifs
            for test in cls._conjuncts(condition)
        ]
        holders = [test for test in tests if secret_words.search(ast.unparse(test))]
        return any(cls._plain_negation(test, keys) for test in holders) and all(
            cls._plain_negation(test, keys) or cls._name_negation(test) for test in holders
        )

    @staticmethod
    def _name_negation(test: ast.expr) -> bool:
        """`k != name`, `k not in names`, `not k == name`, `not k in names`: the entries named are
        dropped and nothing is selected. A `not` around anything else may hide a selection
        (`not (a < 3 or b not in c)`), so it does not count."""
        operators: tuple[type[ast.cmpop], ...] = (ast.NotEq, ast.NotIn)
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            test = test.operand
            operators = (ast.Eq, ast.In)
        return (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], operators)
        )

    @classmethod
    def _conjuncts(cls, condition: ast.expr) -> list[ast.expr]:
        """The operands of the top-level `and`s; an `or` is one opaque operand."""
        if isinstance(condition, ast.BoolOp) and isinstance(condition.op, ast.And):
            return [part for value in condition.values for part in cls._conjuncts(value)]
        return [condition]

    @classmethod
    def _plain_negation(cls, test: ast.expr, keys: set[str]) -> bool:
        """`not <plain test>` and `<word> not in <key>` or `<key> not in <denylist>`: one negation,
        then a test of the key."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return cls._plain_test(test.operand, keys)
        if (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.NotIn)
        ):
            return cls._membership(test.left, test.comparators[0], keys)
        return False

    @classmethod
    def _plain_test(cls, test: ast.expr, keys: set[str]) -> bool:
        """A containment, prefix, suffix or regex test of the key, a membership in a denylist, or
        `any(...)` of such a test."""
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.In):
            return cls._membership(test.left, test.comparators[0], keys)
        if not isinstance(test, ast.Call):
            return False
        function = test.func
        if isinstance(function, ast.Attribute) and function.attr in {"startswith", "endswith"}:
            return cls._mentions(function.value, keys)
        if cls._dotted(function) in cls._REGEX_CALLS:
            return any(cls._mentions(argument, keys) for argument in test.args)
        if (
            isinstance(function, ast.Name)
            and function.id == "any"
            and len(test.args) == 1
            and isinstance(test.args[0], ast.GeneratorExp)
        ):
            return cls._plain_test(test.args[0].elt, keys)
        return False

    @classmethod
    def _membership(cls, left: ast.expr, right: ast.expr, keys: set[str]) -> bool:
        """`<word> in <something made of the key>`, or `<key> in <a collection of names>`: the
        collection is a name, an attribute or a literal, not made of the key and not a string."""
        if cls._mentions(right, keys) and not cls._mentions(left, keys):
            return True
        return (
            cls._mentions(left, keys)
            and not cls._mentions(right, keys)
            and isinstance(right, ast.Name | ast.Attribute | ast.Tuple | ast.List | ast.Set)
        )

    @staticmethod
    def _mentions(node: ast.AST, names: set[str]) -> bool:
        return any(isinstance(part, ast.Name) and part.id in names for part in ast.walk(node))

    # ------------------------------------------------------------------ R2: where the subset goes

    @classmethod
    def flows(cls, tree: ast.AST, node: _Comprehension) -> frozenset[str]:
        """Where the subset goes: CHILD_ENV, ENVIRONMENT_WRITE, UNUSED, RETURNED, YIELDED, SENT,
        WRITTEN, LOGGED, PRINTED, SERIALISED, STORED_ATTRIBUTE, OTHER_CALL or UNFOLLOWED, followed
        through plain names, `X.update(...)`, `X.setdefault(...)` and `X[...] = ...`."""
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        return frozenset(cls._leaves(parents, node, 0))

    @classmethod
    def _leaves(cls, parents: dict[ast.AST, ast.AST], node: ast.AST, hops: int) -> set[str]:
        parent = parents.get(node)
        if parent is None or hops > cls._MAX_HOPS:
            return {"UNFOLLOWED"}
        if isinstance(parent, ast.Return):
            return {"RETURNED"}
        if isinstance(parent, ast.Yield | ast.YieldFrom):
            return {"YIELDED"}
        if isinstance(parent, ast.Await):
            return cls._leaves(parents, parent, hops)
        if isinstance(parent, ast.Expr):
            return {"UNUSED"}
        if isinstance(parent, ast.Assign | ast.AnnAssign):
            targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
            found: set[str] = set()
            for target in targets:
                found |= cls._target_leaves(parents, target, parent, hops)
            return found
        if isinstance(parent, ast.NamedExpr):
            return cls._name_leaves(parents, parent.target.id, parent, hops)
        if isinstance(parent, ast.keyword):
            call = parents.get(parent)
            if not isinstance(call, ast.Call):
                return {"UNFOLLOWED"}
            name = cls._dotted(call.func)
            if parent.arg == "env" and cls.LAUNCHES.search(name):
                return {"CHILD_ENV"}
            return {cls._call_flow(name)}
        if isinstance(parent, ast.Call):
            return cls._argument_leaves(parents, parent, node, hops)
        if isinstance(parent, ast.Starred | ast.Dict | ast.List | ast.Tuple | ast.Set):
            return cls._leaves(parents, parent, hops + 1)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            # a method call on the name that holds the subset: changing the dict leaks nothing
            call = parents.get(parent)
            if not isinstance(call, ast.Call) or call.func is not parent:
                return {"UNFOLLOWED"}
            if parent.attr in {"update", "setdefault", "pop", "clear"}:
                return {"UNUSED"}
            if parent.attr == "copy":
                return cls._leaves(parents, call, hops + 1)
        return {"UNFOLLOWED"}

    @classmethod
    def _target_leaves(
        cls, parents: dict[ast.AST, ast.AST], target: ast.expr, at: ast.stmt, hops: int
    ) -> set[str]:
        if isinstance(target, ast.Name):
            return cls._name_leaves(parents, target.id, at, hops)
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            return cls._name_leaves(parents, target.value.id, at, hops + 1)
        if isinstance(target, ast.Attribute):
            return {"STORED_ATTRIBUTE"}
        return {"UNFOLLOWED"}

    @classmethod
    def _argument_leaves(
        cls, parents: dict[ast.AST, ast.AST], call: ast.Call, node: ast.AST, hops: int
    ) -> set[str]:
        """The subset is an argument of `call`."""
        if node not in call.args:
            return {"UNFOLLOWED"}
        name = cls._dotted(call.func)
        if name in cls.ENVIRONMENT_WRITES:
            return {"ENVIRONMENT_WRITE"}
        function = call.func
        if (
            isinstance(function, ast.Attribute)
            and function.attr in {"update", "setdefault"}
            and isinstance(function.value, ast.Name)
        ):
            return cls._name_leaves(parents, function.value.id, call, hops + 1)
        if name in cls.COPIES or name.endswith(".copy"):
            return cls._leaves(parents, call, hops + 1)
        return {cls._call_flow(name)}

    @classmethod
    def _call_flow(cls, name: str) -> str:
        """What a call named `name` does with an argument."""
        if cls.LAUNCHES.search(name):
            return "UNFOLLOWED"  # a launch given the subset outside `env=`: not proven
        if cls._SENDS.search(name):
            return "SENT"
        if cls._LOGS.search(name):
            return "LOGGED"
        if name in {"print", "pprint", "pprint.pprint"}:
            return "PRINTED"
        if cls._WRITES.search(name):
            return "WRITTEN"
        if cls._SERIALISES.search(name):
            return "SERIALISED"
        return "OTHER_CALL"

    @classmethod
    def _name_leaves(
        cls, parents: dict[ast.AST, ast.AST], name: str, at: ast.AST, hops: int
    ) -> set[str]:
        """Every later read of `name` in its function; a name never read is UNUSED. A name at
        module level is visible to every module that imports it, so a read in this file is not
        all of them: it is followed here, and the result also says UNFOLLOWED."""
        scope: ast.AST = at
        while scope in parents:
            scope = parents[scope]
            if isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.Module):
                break
        first = getattr(at, "lineno", 0)
        reads = [
            part
            for part in ast.walk(scope)
            if isinstance(part, ast.Name)
            and part.id == name
            and isinstance(part.ctx, ast.Load)
            and getattr(part, "lineno", 0) >= first
        ]
        found: set[str] = set() if reads else {"UNUSED"}
        for read in reads:
            found |= cls._leaves(parents, read, hops + 1)
        if not isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            found.add("UNFOLLOWED")
        return found

    @staticmethod
    def _dotted(node: ast.AST) -> str:
        """`a.b.c` for a name or attribute chain, through calls and subscripts; "" otherwise."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            head = EnvironmentSubsets._dotted(node.value)
            return f"{head}.{node.attr}" if head else node.attr
        if isinstance(node, ast.Call | ast.Subscript):
            return EnvironmentSubsets._dotted(
                node.func if isinstance(node, ast.Call) else node.value
            )
        return ""


__all__ = ["EnvironmentSubsets"]
