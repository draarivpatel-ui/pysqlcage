# Good first issues

These starter specifications are small, independently reviewable, and useful. Each should include tests and documentation.

1. Add a `sql_not_in` helper with the same empty-list and parameter-cap semantics as `sql_in`, documenting why `NOT IN` with nullable values can surprise callers.
2. Add a `sql_exists` helper that accepts only a trusted fragment and renders `EXISTS (<fragment>)` without recursion in compilation.
3. Add a `between` helper that validates its column and emits two bound parameters with clear boundary semantics.
4. Add optional identifier case-insensitive matching to `SchemaGuard`, while preserving exact output casing from the schema definition.
5. Add a read-only `explain_fragment_shape` diagnostic that reports fragment nesting depth and parameter count without exposing parameter values.
6. Add a CLI `--max-sql-length` option that is validated against the same bounds as the library API.
7. Add audit support for detecting `EXECUTE` and `EXEC` as dangerous command execution keywords when they appear outside strings.
8. Add an opt-in strict mode to the CLI that treats any uppercase SQL comment or terminator warning as exit status 1 even when future auditors mark it informational.
9. Add JSON output stability tests that sort finding keys and document the machine-readable schema.
10. Add a small benchmark script that measures iterative compilation of legal nesting at depth 32 and reports output size without using recursion.

Before starting one, open an issue or comment so work is not duplicated.
