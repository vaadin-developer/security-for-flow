# Prompt — proxybuilder annotations module (Tier 1/2/3)

> **Status 2026-05-28: DELIVERED in `com.svenruppert:proxybuilder:00.11.00`**
> (lokal published; Maven-Central-Upload steht aus). Das
> `proxybuilder-annotations` Modul ist vorhanden mit allen
> Tier-1/2/3-Annotationen, `@GeneratedByProxyBuilder` ist auf
> `RetentionPolicy.RUNTIME` umgestellt und trägt die fünf erweiterten
> Members. `SecuredAnnotationProcessor` strippt den Marker nicht mehr;
> die generierte Klasse zeigt sowohl `@GeneratedByProxyBuilder` als
> auch `@DelegatesTo` pro Methode. Dieses Dokument bleibt als
> historische Referenz erhalten.
>
> Selbst-kontaminierter Prompt für einen Claude-Agenten, der im
> `proxybuilder`-Repo ein eigenstaendiges `proxybuilder-annotations`-
> Modul anlegt und die hier beschriebenen Annotationen umsetzt.
> Reicht ohne Vorwissen aus einer fremden Session.
>
> Paaren mit `Prompt-proxybuilder-writer-fix.md` — beide gingen in
> denselben Release-Zyklus (writer-fix als 00.10.01, annotations als
> 00.11.00).

---

## Task

Split `com.svenruppert:proxybuilder` into a multi-module build by introducing a new tiny `proxybuilder-annotations` JAR that holds every annotation the project ships. Move the existing `GeneratedByProxyBuilder` there, extend it, and add ten further annotations (Tier 1 + Tier 2 + Tier 3 listed below). Update the processor to honour the new generator-control annotations and emit the runtime-retained marker on every generated type.

## Repo

`com.svenruppert:proxybuilder` (github.com/svenruppert/proxybuilder).
Current Maven Central release: `00.10.00`.
Target the default branch and release as `00.11.00` (minor bump — new module + new API surface; not strictly backwards-compatible because `GeneratedByProxyBuilder` moves package and changes retention).

## Why

Consumers of `proxybuilder` today bind the processor as `<annotationProcessorPath>`, which keeps the processor and all its transitive dependencies (JavaPoet, SLF4J, Dropwizard Metrics) out of the consumer's compile classpath — good. The generated `@GeneratedByProxyBuilder` marker, however, lives in the same JAR; the consumer's compile classpath therefore *also* lacks the annotation, so any reference the processor emits to it triggers a compile error in the consumer module. Workaround in `security-for-flow`'s `SecuredAnnotationProcessor` strips the annotation in `writeDefinedClass`. That is a smell.

Splitting the annotations into a tiny module solves two problems at once:

1. Consumers can add `proxybuilder-annotations` as a regular compile dependency — no transitive bloat, no processor on the classpath.
2. The marker annotation can be bumped to `RetentionPolicy.RUNTIME`, so applications can introspect at runtime which classes are processor-generated (e.g. for audit, instrumentation, prevention of using the un-wrapped original).

The pattern is the same as Google AutoValue (`auto-value-annotations` + `auto-value`), Lombok, MapStruct, Dagger.

## Module structure

```text
proxybuilder-parent              (POM aggregator; existing)
├── proxybuilder-annotations     (new — annotations-only JAR)
└── proxybuilder                 (existing — annotation processor)
```

`proxybuilder-annotations` POM:

- `groupId` = `com.svenruppert`
- `artifactId` = `proxybuilder-annotations`
- `version` = `${project.version}`
- Java compiler release: 26 (same as the rest of the reactor).
- Module name (JPMS): `com.svenruppert.proxybuilder.annotations`
- Dependencies: none, except `com.github.spotbugs:spotbugs-annotations:provided` if you also want the new annotations themselves to be SpotBugs-clean.

`proxybuilder` POM gets:

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>proxybuilder-annotations</artifactId>
  <version>${project.version}</version>
</dependency>
```

so the processor can reference the annotation types when generating code. The processor's `module-info.java` adds `requires transitive com.svenruppert.proxybuilder.annotations;`.

Consumers from this point on:

```xml
<dependencies>
  <dependency>
    <groupId>com.svenruppert</groupId>
    <artifactId>proxybuilder-annotations</artifactId>
    <version>00.11.00</version>
  </dependency>
</dependencies>

<build>
  <plugins>
    <plugin>
      <artifactId>maven-compiler-plugin</artifactId>
      <configuration>
        <annotationProcessorPaths>
          <path>
            <groupId>com.svenruppert</groupId>
            <artifactId>proxybuilder</artifactId>
            <version>00.11.00</version>
          </path>
        </annotationProcessorPaths>
      </configuration>
    </plugin>
  </plugins>
</build>
```

## Annotations — Tier 1 (must)

Package `com.svenruppert.proxybuilder.annotations`. All public.

### 1. `@GeneratedByProxyBuilder` (extended; moved from `com.svenruppert.proxybuilder`)

Marker emitted on every wrapper type. Retention bumped to `RUNTIME` so consumers can introspect.

```java
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface GeneratedByProxyBuilder {
  /** Fully qualified name of the subprocessor that emitted this type
   *  (e.g. "com.svenruppert.vaadin.security.processor.SecuredAnnotationProcessor"). */
  String processor() default "";

  /** Fully qualified name of the source class the wrapper extends. */
  String sourceClass() default "";

  /** proxybuilder version that emitted this type (e.g. "00.11.00"). */
  String proxyBuilderVersion() default "";

  /** ISO-8601 date stamp at emission time. */
  String date() default "";

  /** Free-form comments — e.g. project URL. */
  String comments() default "";
}
```

Migration note: drop the old single `value()` member — the old SOURCE-retention annotation has no Runtime users by definition, so removal is safe. Document this prominently in the CHANGELOG.

### 2. `@SkipProxy`

Tells the processor not to override a particular method (or constructor) in the original class — even if it carries one of the trigger annotations. Useful for fast-path methods, performance-sensitive code, or signatures the processor cannot yet handle. Today's only escape hatch is `final` / `private` / `static`, which has unrelated side effects.

```java
@Documented
@Retention(RetentionPolicy.SOURCE)
@Target({ElementType.METHOD, ElementType.CONSTRUCTOR})
public @interface SkipProxy {
  /** Optional rationale. Surfaces as Diagnostic.Kind.NOTE during processing. */
  String value() default "";
}
```

Processor must:

- Skip any method whose `Element.getAnnotation(SkipProxy.class) != null` during the `defineNewGeneratedMethod` walk.
- Skip annotated constructors during `defineGeneratedConstructorMethod`.
- Emit one `Messager.printMessage(Diagnostic.Kind.NOTE, "skipping (@SkipProxy): " + reason, element)` per skip when `proxybuilder.verbose=true`.

### 3. `@ProxyBuilderOptions`

Per-class override for the processor's compiler options. Today everything is global via `-Aproxybuilder.*`. This annotation lets a consumer fine-tune one specific type.

```java
@Documented
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface ProxyBuilderOptions {
  /** Override the generated-class suffix. Empty string = inherit global. */
  String suffix() default "";

  /** Override the global failOnStaticMethods. DEFAULT = inherit global. */
  FailOnStatic failOnStaticMethods() default FailOnStatic.DEFAULT;

  /** Names of methods to skip wholesale — alternative to placing
   *  @SkipProxy on each one (useful for inherited methods you cannot
   *  annotate). */
  String[] excludeMethodNames() default {};

  enum FailOnStatic { DEFAULT, TRUE, FALSE }
}
```

Processor must:

- Read `@ProxyBuilderOptions` (if present) on the type currently being processed.
- `suffix()`: when non-empty, overrides the value returned by `generatedClassSuffix(TypeElement)`.
- `failOnStaticMethods()`: tri-state — `DEFAULT` keeps the existing global behaviour; `TRUE` / `FALSE` overrides it for this one type.
- `excludeMethodNames()`: every method whose simple name appears in this array is skipped exactly like `@SkipProxy`. Useful when the original method lives in a superclass / interface the consumer cannot edit.

## Annotations — Tier 2 (nice-to-have)

### 4. `@DelegatesTo`

Auto-emitted on every generated method. Lets debuggers, IDEs, and static-analysis tools jump back from a stack-frame in `<Type>Secured.deleteDocument(...)` to the original `DocumentService#deleteDocument(java.lang.String)`.

```java
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface DelegatesTo {
  /** Source-method reference, JLS-style:
   *  "com.example.DocumentService#deleteDocument(java.lang.String)". */
  String value();
}
```

Processor must:

- For every generated wrapper method, add a `@DelegatesTo(...)` annotation with the source class FQN, `#`, method name, parenthesised parameter type FQNs.
- Skip on `@SkipProxy`-skipped methods (they never get generated).
- Honour `proxybuilder.suppressDelegatesTo=true` for users who want stripped output.

### 5. `@WrappedBy`

Hand-applied by the consumer on the original class. Documents the linkage in the opposite direction (original → wrapper). The processor does *not* emit this — it would require source mutation, which compile-time processors cannot do.

```java
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface WrappedBy {
  /** The generated wrapper class. */
  Class<?> value();
}
```

Use case: a static analyser or runtime guard can refuse `new MemberDirectory()` in application code, demanding `new MemberDirectorySecured()` instead. Sample helper to ship under `proxybuilder-annotations`:

```java
public final class ProxyEnforcement {
  public static <T> T requireWrapped(T instance) {
    Class<?> c = instance.getClass();
    WrappedBy wrappedBy = c.getAnnotation(WrappedBy.class);
    if (wrappedBy != null && !wrappedBy.value().isInstance(instance)) {
      throw new IllegalStateException(
        c.getName() + " must be used through its @WrappedBy(" +
        wrappedBy.value().getName() + ") subclass");
    }
    return instance;
  }
}
```

### 6. `@Internal`

Marks proxybuilder's own internal types / methods so consumers know not to subclass them. Resolves audit item P2/21 (no `@Internal` marker present today).

```java
@Documented
@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD,
         ElementType.CONSTRUCTOR, ElementType.FIELD})
public @interface Internal {
  /** Optional reason / migration hint. */
  String reason() default "";
}
```

Apply to: `MethodIdentifier`, `BasicAnnotationProcessor`'s private fields and helper methods, the `addReturnTypeVariables` family. Anything that is not part of the documented Subprocessor SPI.

## Annotations — Tier 3 (optional / when there is actual demand)

Ship the classes, but document them as "experimental / minimal processor support". They consume four lines in the new module each — keep them out of the processor's runtime handling until a consumer asks for them.

### 7. `@ProxyEntry`

```java
@Documented
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.METHOD)
public @interface ProxyEntry {
  /** Free-form rationale. */
  String value() default "";
}
```

Reserved for future generator policies (e.g. "emit additional bootstrap before this method"). The 00.11.00 processor recognises the annotation and emits a `Diagnostic.Kind.NOTE` ("@ProxyEntry is experimental, no-op in 00.11.00").

### 8. `@GeneratedSource`

```java
@Documented
@Retention(RetentionPolicy.SOURCE)
@Target({ElementType.METHOD, ElementType.CONSTRUCTOR, ElementType.FIELD})
public @interface GeneratedSource {
  /** Subprocessor that contributed this member. */
  String processor() default "";
}
```

For future partially-generated classes: distinguishes processor-emitted members from manually-written ones within the same class. The 00.11.00 processor does not emit `@GeneratedSource` itself; consumers may add it manually for documentation.

### 9. `@ProxyName`

```java
@Documented
@Retention(RetentionPolicy.SOURCE)
@Target(ElementType.TYPE)
public @interface ProxyName {
  /** Pattern with placeholder {Original}, e.g. "{Original}WithSecurity". */
  String value();
}
```

Per-class override that beats `@ProxyBuilderOptions.suffix()`. Useful when the wrapper name should not be a simple suffix concatenation. Processor must:

- Look for `@ProxyName` first; if present, expand `{Original}` against the source class simple name and use that.
- Fall back to `@ProxyBuilderOptions.suffix()` if `@ProxyName` is absent.
- Fall back to the global `proxybuilder.suffix` option (existing behaviour) if neither is present.
- Fall back to `responsibleFor().getSimpleName()` (existing behaviour) as ultimate default.

## Processor changes (`proxybuilder` module)

1. Replace `import com.svenruppert.proxybuilder.GeneratedByProxyBuilder` with `import com.svenruppert.proxybuilder.annotations.GeneratedByProxyBuilder` everywhere.
2. Update `BasicAnnotationProcessor.createAnnotationSpecGenerated()`:
   ```java
   private AnnotationSpec createAnnotationSpecGenerated(TypeElement source) {
     return AnnotationSpec.builder(GeneratedByProxyBuilder.class)
         .addMember("processor", "$S", this.getClass().getName())
         .addMember("sourceClass", "$S",
             elementUtils.getBinaryName(source).toString())
         .addMember("proxyBuilderVersion", "$S", ProxyBuilderVersion.VERSION)
         .addMember("date", "$S", LocalDateTime.now().format(DateTimeFormatter.ISO_DATE_TIME))
         .addMember("comments", "$S", "www.proxybuilder.org")
         .build();
   }
   ```
   `ProxyBuilderVersion.VERSION` is a new package-private constant set by a Maven resource filter (or hard-coded in source for `00.11.00`).
3. Add `applyProxyBuilderOptions(TypeElement)` early in `process(...)` to read `@ProxyBuilderOptions` and `@ProxyName`, caching the resolved suffix and the static-method policy per type.
4. Wire `@SkipProxy` + `excludeMethodNames` into the existing `defineNewGeneratedMethod` and `defineGeneratedConstructorMethod` filters.
5. Wire `@DelegatesTo` emission into `defineDelegatorMethod` (add an `AnnotationSpec` to the `MethodSpec.Builder` before `build()`).
6. Add a new compiler option constant `OPTION_SUPPRESS_DELEGATES_TO = "proxybuilder.suppressDelegatesTo"` and update `@SupportedOptions` accordingly.
7. Update `module-info.java`:
   ```text
   exports com.svenruppert.proxybuilder.annotations;   // delete — now in proxybuilder-annotations
   requires transitive com.svenruppert.proxybuilder.annotations;
   ```

## Regression tests

Use `com.google.testing.compile:compile-testing:0.21.0`. Tests live in the `proxybuilder` module (where the processor is) but consume `proxybuilder-annotations` as a regular compile dependency.

Minimum coverage:

- **`@GeneratedByProxyBuilder` is emitted with `RetentionPolicy.RUNTIME`** — assert the generated source contains both `@GeneratedByProxyBuilder` and member values (`processor="…"`, `sourceClass="…"`, `proxyBuilderVersion="00.11.00"`).
- **`@SkipProxy` skips a method** — given a source with two methods, one carrying `@SkipProxy`, the generated wrapper must override only the unannotated one.
- **`@ProxyBuilderOptions.suffix()` overrides the global suffix** — wrapper name uses the per-class suffix.
- **`@ProxyBuilderOptions.failOnStaticMethods() = FALSE`** — a static method with a trigger annotation produces a `WARNING`, not an `ERROR`, even with global default `true`.
- **`@ProxyBuilderOptions.excludeMethodNames()` skips named methods.**
- **`@DelegatesTo` annotation is emitted on every generated method**, with the FQN of the source method.
- **`proxybuilder.suppressDelegatesTo=true`** strips `@DelegatesTo` from the output.
- **`@ProxyName("{Original}WithLogging")`** beats `@ProxyBuilderOptions.suffix()` when both are present.
- **Migration smoke test**: a source that does NOT use any of the new annotations still produces the same wrapper shape as `00.10.00` (modulo the new `@GeneratedByProxyBuilder` retention + members).

Also: assert that the runtime annotation can be read back:

```java
GeneratedByProxyBuilder meta =
    DocumentServiceSecured.class.getAnnotation(GeneratedByProxyBuilder.class);
assertThat(meta).isNotNull();
assertThat(meta.sourceClass()).isEqualTo("test.DocumentService");
assertThat(meta.proxyBuilderVersion()).isEqualTo("00.11.00");
```

## Documentation

In `proxybuilder-annotations/README.md`:

- Two-paragraph intro: "Annotations consumed and emitted by the proxybuilder annotation processor. Use this module on the compile classpath; pair it with `proxybuilder` on `<annotationProcessorPaths>`."
- One-line table of every annotation with its target + retention + tier.

In `proxybuilder/README.md` (top-level CHANGELOG entry for `00.11.00`):

- "split annotations into `proxybuilder-annotations`"
- "GeneratedByProxyBuilder is now RetentionPolicy.RUNTIME; old SOURCE-retention copy in `com.svenruppert.proxybuilder` is removed (breaking)"
- "added @SkipProxy, @ProxyBuilderOptions, @DelegatesTo, @WrappedBy, @Internal (Tier 1/2)"
- "added @ProxyEntry, @GeneratedSource, @ProxyName (Tier 3 — minimal processor support)"
- "fix: close generated-source writer (see companion writer-fix prompt)"

## Verification checklist

- [ ] `mvn -q clean install` green on JDK 26 for both modules.
- [ ] `proxybuilder-annotations` JAR contains ten annotation types + the `ProxyEnforcement` helper, nothing else.
- [ ] `proxybuilder` JAR no longer contains `com.svenruppert.proxybuilder.GeneratedByProxyBuilder`.
- [ ] All compile-testing tests green (existing + new).
- [ ] Downstream smoke test against an `@Secured`-using consumer compiles WITHOUT putting `proxybuilder` itself on the compile classpath.
- [ ] Reading `@GeneratedByProxyBuilder` via reflection at runtime returns the populated members.
- [ ] `@SkipProxy`-annotated methods are absent from the wrapper.
- [ ] CHANGELOG entry written.
- [ ] Maven Central artifacts staged under `00.11.00`, both modules signed + published.

## Constraints

- No CGLIB, ByteBuddy, or other bytecode tooling — keep proxybuilder JDK-only.
- No transitive dependencies from `proxybuilder-annotations` other than possibly `spotbugs-annotations:provided`. The whole point is keep it tiny.
- The companion fix from `Prompt-proxybuilder-writer-fix.md` ships in the same `00.11.00` release.
- No formatter / license-header churn outside the touched files.
- One commit per logical block is fine (e.g. "module split", "new annotations", "processor wiring"), but they should all land before the `00.11.00` tag.
- Commit message style: conventional commits (`feat`, `fix`, `refactor`); no `Co-Authored-By:` footer, no "Generated with …" footer.
