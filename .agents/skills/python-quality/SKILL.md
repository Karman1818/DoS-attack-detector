---
name: python-quality
description: >-
  Enforces modern Python 3.12+ engineering practices, strict static typing with mypy,
  idiomatic error handling, and Ruff formatting and linting conventions. Use when writing,
  reviewing, or refactoring Python modules.
---

# Python Quality & Engineering Standards

This skill guides the implementation of clean, idiomatic, and strictly-typed Python code within the `dos-attack-detector` codebase.

---

## 1. Core Engineering Principles

1. **Python 3.12+ Modern Idioms**:
   - Use built-in generics (e.g., `list[str]`, `dict[str, int]`, `tuple[int, ...]`) instead of `typing.List` or `typing.Dict`.
   - Use union syntax (`int | None`) instead of `Optional[int]`.
   - Prefer `collections.abc.Sequence` or `collections.abc.Iterable` for input arguments to maximize flexibility.
2. **Immutable Domain Objects**:
   - Model all packets, features, and alerts with `@dataclass(frozen=True, slots=True)`.
   - Frozen dataclasses prevent accidental state mutations and reduce memory footprint via `slots=True`.
3. **Explicit Error Handling**:
   - Never use bare `except:` or `except Exception: pass`.
   - Catch specific exceptions (e.g., `FileNotFoundError`, `ValueError`, `scapy.error.Scapy_Exception`).
   - Include actionable context in exception messages.

---

## 2. Type Hinting & Mypy Guidelines

The project enforces `strict = true` in `pyproject.toml`.

- **Function Signatures**: Every public and private function must have type annotations for all parameters and its return type (`-> None`, `-> list[DetectionAlert]`, etc.).
- **Missing Third-Party Stubs**: For libraries without official PEP 561 stubs (such as Scapy or parts of pandas), do not use `# type: ignore` across business logic. Instead, isolate the call or rely on the configured module override in `pyproject.toml`.
- **Validation**:
  ```bash
  uv run mypy src
  ```

---

## 3. Ruff Linting & Formatting Standards

Ruff acts as both the linter (replacing flake8, isort, bandit, pydocstyle) and code formatter (replacing Black).

### Quality Checklist Before Committing
- [ ] Line length does not exceed 100 characters.
- [ ] Imports are sorted alphabetically and grouped: Standard library -> Third party -> Local package (`dos_detector`).
- [ ] Security rules (`S` series from flake8-bandit) pass with zero warnings.
- [ ] Code is formatted:
  ```bash
  uv run ruff format .
  uv run ruff check --fix .
  ```

---

## 4. Explaining Decisions to Junior Developers
- When introducing a pattern (e.g., Protocol vs. ABC, or Dataclass vs. Pydantic), explain **why** the choice was made (e.g., standard library zero-overhead vs. runtime validation overhead).
- Provide before/after code snippets demonstrating the cleaner or safer approach.
