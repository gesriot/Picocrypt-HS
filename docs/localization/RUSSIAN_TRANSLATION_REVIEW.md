# Russian Translation Review

<!-- markdownlint-disable MD013 -->

This note is the release gate for the first curated Russian UI translation in
Picocrypt-NG. It is not a Weblate round-trip proof and must not be used to open
the Fyne Weblate component. Weblate setup remains governed by
`docs/localization/WEBLATE_SETUP.md`.

Review date: 2026-07-09.

Scope:

- Fyne desktop/mobile catalog: `src/internal/ui/translation/ru.json`
- Android resources: `android/app/src/main/res/values-ru/strings.xml`
- CLI: out of scope and still English-only

## Terminology Decisions

| English | Russian | Notes |
| --- | --- | --- |
| Encrypt | Зашифровать | Do not use "закодировать". |
| Decrypt | Расшифровать | Do not use "открыть" or "разблокировать". |
| Password | пароль | Keep separate from keyfile. |
| Keyfile | ключевой файл | Do not shorten to "ключ" in UI copy. |
| Volume | том, зашифрованный том | Use the longer form when deletion or integrity risk is discussed. |
| Deniability | правдоподобное отрицание | Do not translate as anonymity, invisibility, or hidden mode. |
| Force decrypt | принудительная расшифровка | This is not repair or safe recovery. |
| Integrity check | проверка целостности | Failed integrity means output is unverified and may be corrupted. |
| Plaintext metadata | открытые метаданные | Comments are not private or encrypted. |
| Output | результат, выходной файл | Prefer "результат" in warnings and save flows. |

## High-Risk Copy Checks

- Authentication failure says to check password, keyfiles, and keyfile order.
  It does not claim that only the password is wrong.
- Force decrypt copy says the result is unverified and may be corrupted. It
  does not promise recovery.
- Comments are described as plaintext/open metadata. They are never called
  private, secret, encrypted, or protected.
- Deniability copy avoids anonymity, invisibility, hidden-mode, and guaranteed
  undetectability claims.
- Destructive labels name the object where ambiguity matters: source files,
  encrypted volume, temporary files, or result.
- Russian counted strings use real plural forms instead of `file(s)`-style
  shortcuts.

## Verification Requirements

The Russian translation must keep these checks green:

- Fyne JSON parses as UTF-8 and matches `translation/en.json` keys, plural
  shape, and template placeholders.
- Fyne runtime selection of `ru` exercises Russian plural forms for one, few,
  and many.
- Android `values-ru/strings.xml` mirrors every translatable base string and
  plural resource.
- Android Russian plurals define `one`, `few`, `many`, and `other`.
- Android resources preserve positional placeholders.
- CLI localization guards stay green.

Manual UI smoke is still recommended before release because Russian strings are
longer than English, especially in warnings and Android storage guidance.
