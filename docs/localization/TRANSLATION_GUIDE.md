# Picocrypt-NG Translation Guide

<!-- markdownlint-disable MD013 MD060 -->
<!-- Wide multilingual tables are intentional in this glossary-style document. -->

This guide defines the translation foundation for Picocrypt-NG. It is not a
string catalog and does not enable localization by itself. It defines the voice,
terminology, review rules, and tooling constraints that every future translation
or Weblate import must follow.

Picocrypt-NG is a security-sensitive encryption app. Translation quality is a
security UX concern: translated strings must not promise stronger protection
than the implementation provides, hide risk, or blur authentication,
integrity, password, keyfile, corruption, and deletion concepts.

## Scope

| Surface | Current state | Translation path |
|---|---|---|
| Desktop Fyne UI | User-facing strings are mostly Go literals under `src/internal/ui` and `src/internal/app`. | Use Fyne `fyne.io/fyne/v2/lang` catalogs after strings are extracted. |
| Android app | Many strings already live in `android/app/src/main/res/values/strings.xml`; some Kotlin user messages are still hard-coded. | Continue with Android string resources. |
| CLI | Cobra help, prompts, warnings, and errors are hard-coded Go strings. | Do not localize CLI output, command names, flags, or examples. Keep CLI English-only. |
| Web/WASM | The Go WASM bridge exports functions and numeric error codes; it does not own the hosted web UI copy. | Localize the web frontend separately if/when that source is brought into scope. |

Non-goals for the first localization phase:

- Do not modify `crypto`, `header`, `keyfile`, or `volume` semantics.
- Do not translate flags, environment variables, file extensions, protocol names,
  code identifiers, or volume-format fields.
- Do not localize the CLI. CLI help, prompts, errors, stdout/stderr, command
  names, flags, and examples are an English scripting contract.
- Do not translate comments stored inside user volumes. Those are user data.
- Do not add Weblate before stable string IDs, a glossary, and review rules exist.

## String Source Of Truth

Do not maintain a full manual string registry in this guide. Full registries
drift from code and become a second source of truth.

The source of truth is platform-native:

| Surface | Source of truth | Rule |
|---|---|---|
| Android app | `android/app/src/main/res/values/strings.xml` | The base English file owns Android UI strings that are already resource-backed. Hard-coded Kotlin user messages must be externalized before a locale can be released for Android. |
| Desktop Fyne UI | `src/internal/ui/translation/en.json` after Fyne localization is wired | Do not add a dead `en.json`. Create it in the same change that embeds Fyne translations and replaces UI literals with `lang.L`, `lang.X`, `lang.N`, or `lang.XN`. |
| CLI | none | CLI is not localized. |
| Web/WASM | external web frontend source, if brought into scope | Do not add web UI strings to the Go WASM bridge. |

This guide owns terminology, review rules, and security-critical context. It
does not own every button label or status string.

## Authoritative Sources

Use these sources before adding or changing localization mechanics:

- Fyne app translations: <https://docs.fyne.io/explore/translations/>
- Fyne `lang` package API: <https://docs.fyne.io/api/v2/lang/pkg/>
- Android localization: <https://developer.android.com/guide/topics/resources/localization>
- Android string resources and plurals: <https://developer.android.com/guide/topics/resources/string-resource>
- Android language and layout support: <https://developer.android.com/training/basics/supporting-devices/languages>
- Android pseudolocales: <https://developer.android.com/guide/topics/resources/pseudolocales>
- Weblate Android resources: <https://docs.weblate.org/en/latest/formats/android.html>
- Weblate JSON formats: <https://docs.weblate.org/en/latest/formats/json.html>
- Weblate i18next formats: <https://docs.weblate.org/en/latest/formats/i18next.html>
- Weblate gettext formats: <https://docs.weblate.org/en/latest/formats/gettext.html>
- Weblate quality checks: <https://docs.weblate.org/en/latest/user/checks.html>
- Weblate hosted pricing and Libre plan: <https://weblate.org/en/hosting/>
- Unicode CLDR plural rules: <https://cldr.unicode.org/index/cldr-spec/plural-rules>
- Unicode LDML / locale identifiers: <https://www.unicode.org/reports/tr35/>
- Microsoft Localization Style Guides: <https://learn.microsoft.com/en-us/globalization/reference/microsoft-style-guides>
- Microsoft Terminology: <https://learn.microsoft.com/en-us/globalization/reference/microsoft-terminology>
- Microsoft Writing Style Guide: <https://learn.microsoft.com/en-us/style-guide/welcome/>
- Google developer translation guidance: <https://developers.google.com/style/translation>
- ANSSI CyberDico: <https://cyber.gouv.fr/cyberdico/>
- INCIBE cybersecurity glossary: <https://www.incibe.es/sites/default/files/contenidos/guias/doc/guia_glosario_ciberseguridad_2021.pdf>

Use Microsoft terminology as practical UI terminology, not as a cryptographic
specification. When it conflicts with Picocrypt-NG semantics, this guide wins.

## Tooling Contract

### Fyne desktop

Fyne supports app translations through `fyne.io/fyne/v2/lang`.

- Put embedded JSON translation files under a `translation` directory.
- Load them with `lang.AddTranslationsFS`.
- Use `lang.Localize` / `lang.L` for direct source-string translation.
- Use `lang.LocalizeKey` / `lang.X` where the English string is ambiguous.
- Use plural APIs for counted strings instead of building `file(s)` strings.
- Keep `en.json` complete. Locale matching should have a generic language file
  when region-specific variants exist; for example, do not add only `fr-FR.json`
  if `fr.json` is missing.
- `en.json` must use Fyne's object shape, not an array of objects:
  `"string.id": "English text"` for singular strings and
  `"string.id": {"one": "...", "other": "..."}` for plurals.
- Prefer stable keyed strings for ambiguous or security-critical copy. Examples:
  `auth.failed.body`, `force_decrypt.warning`,
  `comments.plaintext_warning`, `delete.encrypted_volume`,
  `deniability.header_preview`.
- Do not put translator comments in Fyne JSON. Keep context in this guide,
  Weblate component metadata, or a review-only companion file.

Before connecting Fyne JSON to Weblate, run a round-trip test on the exact Fyne
JSON shape Picocrypt-NG uses. Generic Weblate JSON is useful for simple key/value
files, but its plain JSON format does not carry all plural/context metadata.

### Android

Android must use native string resources.

- `android/app/src/main/res/values/strings.xml` is the base English file for
  resource-backed Android UI strings.
- Translations live under locale resource directories such as `values-ru`,
  `values-fr`, `values-de`, `values-es`, `values-it`, or Android BCP-47 style
  qualifiers where needed.
- Before enabling an Android locale, remove or map remaining hard-coded
  user-facing Kotlin messages for that localized surface. Do not translate raw
  Go error text as source copy.
- Use positional placeholders such as `%1$s` and `%1$d` so translators can
  reorder arguments.
- Use `<plurals>` for counted strings. Do not write `file(s)`.
- Mark non-translatable technical strings with `translatable="false"` when they
  are resource-backed.
- Run Android pseudolocale checks before accepting broad UI localization.

Weblate setup for Android should use:

- File mask: `android/app/src/main/res/values-*/strings.xml`
- Base language file: `android/app/src/main/res/values/strings.xml`
- Format: Android String Resource

### CLI

CLI localization is out of scope. Cobra command names, flags, shell examples,
exit behavior, stdout/stderr, and scripting contracts must stay English-only.
Do not add CLI catalogs or locale-driven CLI output.

### Web/WASM

The Go WASM bridge should not grow UI strings just to support localization. Keep
the bridge API stable and localize the hosted web frontend where the UI lives.

### Hosted Weblate

As of 2026-07-08, Weblate's official pricing page says libre public projects can
use a hosted Libre plan gratis, with the same limits as the 160k hosted plan.
Verify the current terms before setup. Self-hosting remains the fallback if the
hosted eligibility rules change or if Picocrypt-NG needs stricter operational
control.

Failing Weblate checks for placeholders, XML validity, tags, whitespace,
newlines, plurals, or glossary rules are release blockers unless a maintainer
records a concrete reason for accepting the warning.

## Voice And Style

Use a calm, precise, non-marketing voice.

Good:

- "Verify integrity before decryption."
- "The kept output is unverified and may be corrupted."
- "Comments are plaintext metadata."

Bad:

- "Your data is completely safe."
- "Repair damaged files."
- "Comments are private."
- "Wrong password" when keyfiles, keyfile order, or corruption may be the cause.

General rules:

- Prefer direct action labels for buttons.
- State destructive actions explicitly.
- State known facts as facts. Use "may" only when the result is uncertain.
- Do not blame the user in errors.
- Do not make warnings sound like optional hints when data loss or unverifiable
  output is possible.
- Keep security terms consistent even when a shorter synonym sounds nicer.

Language-specific voice:

| Language | Voice choice |
|---|---|
| Russian | Neutral technical Russian. Prefer concise imperatives or impersonal wording. Avoid bureaucratic phrases like "выполнить удаление". |
| French | Use `vous` in instructions. Use natural French security terms, not literal English calques. |
| German | Use formal-neutral `Sie` in instructions. Avoid English Title Case. Split long compounds with hyphens when readability suffers. |
| Spanish | Use neutral international Spanish. Avoid regional-only terms and avoid relying on either `tú` or `usted` where an impersonal UI phrase works. |
| Italian | Use concise UI actions and impersonal wording. Prefer short labels; use longer technical forms in explanatory text when needed. |

## Product Glossary

Use these translations unless a maintainer deliberately changes the glossary.

| English concept | Russian | French | German | Spanish | Italian |
|---|---|---|---|---|---|
| Encrypt | Зашифровать | Chiffrer | Verschlüsseln | Cifrar | Cifra |
| Encryption | Шифрование | Chiffrement | Verschlüsselung | Cifrado | Crittografia |
| Decrypt | Расшифровать | Déchiffrer | Entschlüsseln | Descifrar | Decifra |
| Decryption | Расшифровка | Déchiffrement | Entschlüsselung | Descifrado | Decrittografia |
| Password | Пароль | Mot de passe | Passwort | Contraseña | Password |
| Confirm password | Повторите пароль | Confirmer le mot de passe | Passwort bestätigen | Confirmar contraseña | Conferma password |
| Keyfile | Ключевой файл | Fichier-clé | Schlüsseldatei | Archivo de clave | File chiave |
| Keyfile order matters | Порядок ключевых файлов важен | L'ordre des fichiers-clés est important | Die Reihenfolge der Schlüsseldateien ist wichtig | El orden de los archivos de clave importa | L'ordine dei file chiave è importante |
| Plaintext metadata | Открытые метаданные | Métadonnées en clair | Klartext-Metadaten | Metadatos en texto claro | Metadati in chiaro |
| Comments are plaintext metadata | Комментарии хранятся как открытые метаданные | Les commentaires sont des métadonnées en clair | Kommentare sind unverschlüsselte Klartext-Metadaten | Los comentarios son metadatos en texto claro | I commenti sono metadati in chiaro |
| Deniability | Правдоподобное отрицание | Déni plausible | Glaubhafte Abstreitbarkeit | Negación plausible | Negabilità plausibile |
| Paranoid mode | Параноидальный режим | Mode paranoïaque | Paranoid-Modus | Modo paranoico | Modalità paranoica |
| Verify integrity first | Сначала проверить целостность | Vérifier d'abord l'intégrité | Integrität zuerst prüfen | Verificar primero la integridad | Verifica prima l'integrità |
| Force decrypt | Принудительная расшифровка | Forcer le déchiffrement | Entschlüsselung erzwingen | Forzar descifrado | Forza decifratura |
| Reed-Solomon | Reed-Solomon | Reed-Solomon | Reed-Solomon-Fehlerkorrektur | Reed-Solomon | Reed-Solomon |
| Compress | Сжать | Compresser | Komprimieren | Comprimir | Comprimi |
| Split | Разбить на части | Fractionner | Aufteilen | Dividir | Dividi |
| Auto unzip | Автоматически распаковать ZIP | Décompresser automatiquement | ZIP automatisch entpacken | Descomprimir automáticamente | Estrai automaticamente lo ZIP |
| Delete files | Удалить исходные файлы | Supprimer les fichiers | Dateien löschen | Eliminar archivos | Elimina i file originali |
| Delete volume | Удалить зашифрованный том | Supprimer le volume | Volume löschen | Eliminar volumen | Elimina il volume cifrato |
| Output may be corrupted | Вывод может быть поврежден | La sortie peut être corrompue | Die Ausgabe kann beschädigt sein | La salida puede estar dañada | Il file di output potrebbe essere danneggiato |
| Authentication error | Ошибка аутентификации | Erreur d'authentification | Authentifizierungsfehler | Error de autenticación del volumen | Errore di autenticazione |
| Data corruption detected | Обнаружено повреждение данных | Corruption des données détectée | Datenbeschädigung erkannt | Se detectó corrupción de datos | Rilevato danneggiamento dei dati |

Notes:

- Italian UI labels use `Cifra` and `Decifra` for compactness. Longer explanatory
  text may use `crittografare`, `crittografia`, `decrittografare`, or
  `decrittografia` when the sentence needs the technical noun.
- German may use `Datenintegrität` when the object is data integrity rather than
  a generic integrity check.
- Russian may use "проверка подлинности" in broad user-facing text, but
  "аутентификация" is the preferred compact cryptographic UI term here.

## Forbidden Or Dangerous Translations

Do not use these unless a maintainer explicitly approves the exception.

| English concept | Avoid | Why |
|---|---|---|
| Encrypt | encode, codificar, kodieren, закодировать | Encoding is not encryption. |
| Decrypt | open, unlock, apri, sblocca, décrypter, decodificar | Decryption is not ordinary opening; French `décrypter` can imply breaking without the key. |
| Password | key, code, clave, clé, chiave | Passwords and keyfiles are different credentials. |
| Keyfile | key, llave, Schlüssel, ключ | A keyfile is a user-provided file, not only a cryptographic key. |
| Comments | secret notes, private comments | Picocrypt-NG comments are plaintext header metadata. |
| Plaintext metadata | public data, unprotected data | "Public" and "unprotected" overstate or blur the format nuance. |
| Deniability | anonymity, invisibility, hidden mode | Deniability is not anonymity and not a guarantee of being unnoticed. |
| Paranoid mode | maximum security, ultra secure | The mode adds defense in depth; it does not guarantee absolute security. |
| Force decrypt | repair, recover safely, ignore errors | Forced decrypt keeps unverified output and can produce corrupted data. |
| Authentication error | authorization error, login failed | Volume authentication is not account login or access control. |
| Delete | remove from list, clear | Deletion must say what data is actually deleted. |

## Security-Critical Copy Rules

### Authentication

Do not translate authentication failures as "wrong password" unless code knows
the password alone is wrong. In Picocrypt-NG, authentication can fail because of:

- wrong password;
- missing or wrong keyfiles;
- wrong keyfile order;
- damaged or modified volume data;
- unsupported or corrupted header state.

Preferred pattern:

> Authentication failed. Check the password, keyfiles, and keyfile order.

### Integrity and force decrypt

Force decrypt must sound dangerous. It is not repair.

Preferred pattern:

> Integrity check failed. The kept output is unverified and may be corrupted.

Never say the output was recovered safely.

### Comments

Comments stored in volumes are plaintext header metadata. Do not call them
secret, private, encrypted, or protected. Current v2 volumes authenticate header
metadata, including comments, but that does not make comments confidential.

Preferred short pattern:

> Comments are plaintext metadata. Do not put secrets here.

### Deniability

Deniability means plausible deniability of the volume shape, not anonymity.
Avoid "hidden", "anonymous", "invisible", or "undetectable" unless the exact
implementation behavior has been verified for that sentence.

### Delete actions

Always name the object:

- delete input files;
- delete original files;
- delete encrypted volume;
- delete temporary files.

Do not use a generic "delete" label where the user can confuse source files,
output files, keyfiles, and volumes.

## Security-Critical String Registry

Keep this registry small. It covers strings where translation can change
security meaning. It is not a full application string list.

| Risk class | Meaning | Required translator context |
|---|---|---|
| `P0-auth` | Authentication, password, keyfiles, keyfile order, header tamper, and corruption ambiguity. | Failure is not necessarily a wrong password or account-login failure. |
| `P0-integrity` | Verify-first, MAC/integrity checks, corrupted data, force decrypt, and kept output. | Forced output is unverified and may be corrupted; do not describe it as repaired. |
| `P0-deniability` | Deniable wrapper and unreadable header/metadata before decryption. | Deniability is not anonymity, invisibility, or a hidden mode. |
| `P0-metadata` | Comments and header metadata. | Comments are plaintext metadata and must not be described as private or secret. |
| `P1-destructive` | Delete input files, delete encrypted volume, discard output, and temporary cleanup. | Name the deleted or discarded object explicitly. |
| `P1-credential-handling` | Generate, copy, paste, clear password, non-ASCII password normalization, and keyfile creation. | Keep password, keyfile, and key distinct. Mention clipboard or typing risks when present in source. |
| `P2-crypto-options` | Paranoid mode, Reed-Solomon, compression, split, auto-unzip. | Describe behavior, not absolute security or guaranteed repair. |
| `P2-file-flow` | File/folder selection, output naming, app storage, staging, and free-space warnings. | Preserve object identity: input file, output file, volume, folder, temporary file. |
| `P3-status-accessibility` | Progress, foreground service, content descriptions, generic buttons. | Keep status concise and avoid turning state labels into promises. |

Initial high-risk entries:

| Surface | ID or source | Risk class | Translator note |
|---|---|---|---|
| Android | `force_decrypt_warning` | `P0-integrity` | Force decrypt keeps unverified output; it does not repair data. |
| Android | `authentication_error` | `P0-auth` | This is volume authentication, not login or account authorization. |
| Android | `comments_plaintext_warning` | `P0-metadata` | Comments are plaintext metadata; do not call them private. |
| Android | `comments_not_readable` | `P0-deniability` | Deniability prevents previewing comments before decryption. |
| Android | `deniability_note` | `P0-deniability` | Header metadata cannot be previewed before decryption; this is not anonymity. |
| Android | `keyfiles_required_warning` | `P0-auth` | A keyfile is a user-provided file credential, not a password or cryptographic key label. |
| Android | `keyfile_order_matters` | `P0-auth` | Preserve that the order of keyfiles is required. |
| Android | `discard_output` | `P1-destructive` | The output is discarded/cleaned up, not merely dismissed. |
| Fyne desktop | future `force_decrypt.warning` | `P0-integrity` | Same invariant as Android `force_decrypt_warning`. |
| Fyne desktop | future `deniability.header_preview` | `P0-deniability` | Preserve "may" when header preview cannot prove deniability. |
| Fyne desktop | future `comments.plaintext_warning` | `P0-metadata` | Prefer "plaintext metadata" over "not encrypted" alone. |
| Fyne desktop | future `delete.encrypted_volume` | `P1-destructive` | Name the encrypted volume, not a generic delete action. |

## Placeholders, Plurals, And Escaping

- Preserve placeholders exactly: `%s`, `%d`, `%1$s`, `%1$d`, `{name}`,
  `{count}`, `{{ value }}`, and similar markers are not words.
- Use numbered placeholders when a platform supports them.
- Do not concatenate translated sentence fragments in code.
- Do not use `file(s)`. Use platform plural support.
- Every plural resource must have the platform-required fallback form, normally
  `other`.
- Keep keyboard shortcuts, command names, flags, environment variables, file
  extensions, MIME identifiers, package IDs, and URLs unchanged.
- Android XML strings must escape XML-sensitive characters and Android-sensitive
  leading characters correctly.
- Fyne JSON strings must remain valid UTF-8 JSON and must preserve any template
  markers consumed by Fyne `lang`.

## Reviewer Checklist

Every localization PR or Weblate merge must answer these checks:

1. Does the translation preserve Picocrypt-NG's security meaning?
2. Are password, keyfile, authentication, integrity, and corruption terms
   distinct?
3. Does any string overpromise confidentiality, recovery, deniability, or
   security?
4. Are comments described as plaintext metadata?
5. Does force decrypt clearly say the output is unverified and may be corrupted?
6. Are destructive actions explicit about what gets deleted?
7. Are all placeholders preserved and ordered correctly?
8. Are counted strings implemented through plural resources?
9. Are Weblate checks clean, or is every accepted warning documented?
10. Has the relevant UI been checked for clipped text, especially German and
    Russian strings?
11. Has Android been checked with pseudolocales after large resource changes?
12. Are non-translatable identifiers marked or excluded from translation?
13. Does the change leave CLI output untouched?

## Implementation Readiness Gates

Before enabling a locale in a release:

- The locale has a glossary review against this guide.
- Android resources compile.
- Fyne catalogs load without runtime errors.
- No enabled localized surface still depends on hard-coded user-facing source
  text that bypasses the platform catalog.
- Weblate or local validation reports no unresolved placeholder/plural/XML
  issues.
- The translated UI has been manually smoke-tested for core workflows:
  selecting files, encrypting, decrypting, keyfiles, comments, force decrypt,
  verify-first, deletion options, and error dialogs.
- Release notes mention localization as user-facing UI work, not as a
  cryptographic change.
