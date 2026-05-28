# Prompt — proxybuilder writer-lifecycle fix

> **Status 2026-05-28: DELIVERED in `com.svenruppert:proxybuilder:00.10.01`**
> (Maven Central). Der Writer-Close-Workaround im
> `SecuredAnnotationProcessor.writeDefinedClass` wurde entsprechend
> entfernt. Dieses Dokument bleibt als historische Referenz erhalten.
>
> Selbst-kontaminierter Prompt für einen Claude-Agenten, der im
> `proxybuilder`-Repo den in `Anforderungen-proxybuilder-modernisierung.md`
> als `[!]` markierten Defekt behebt (Writer wird in `writeDefinedClass`
> nicht geschlossen — bricht Tests mit
> `com.google.testing.compile`). Reicht ohne Vorwissen aus dieser Session.

---

## Task

Fix a writer-lifecycle defect in `BasicAnnotationProcessor.writeDefinedClass(String, TypeSpec.Builder)` and add a regression test that exercises the path through `com.google.testing.compile`.

## Repo

`com.svenruppert:proxybuilder` (github.com/svenruppert/proxybuilder).
Released version on Maven Central: `00.10.00`.
Target the default branch and release as `00.10.01` (patch bump).

## Symptom

Downstream projects that build an annotation processor on top of
`BasicAnnotationProcessor` (or `BasicStaticProxyAnnotationProcessor`)
and write JUnit tests with `com.google.testing.compile:compile-testing`
0.21.0 see this:

```
java.lang.RuntimeException: java.io.FileNotFoundException
    at com.google.testing.compile.JavaFileObjectSubject.contentsAsString(JavaFileObjectSubject.java:108)
    ...
Caused by: java.io.FileNotFoundException
    at com.google.testing.compile.InMemoryJavaFileManager$InMemoryJavaFileObject.openInputStream(InMemoryJavaFileManager.java:187)
```

The generated source file is registered in compile-testing's
`InMemoryJavaFileManager`, but reading its content via
`contentsAsUtf8String()` / `openReader()` / `openInputStream()`
throws `FileNotFoundException` with no message and no cause.

Real javac (e.g. on a Maven build) does NOT exhibit this — the
generated file is correct and downstream compilation succeeds.

## Root cause

In `src/main/java/com/svenruppert/proxybuilder/BasicAnnotationProcessor.java`,
method `writeDefinedClass(String, TypeSpec.Builder)`:

```java
try {
  JavaFileObject jfo = filer.createSourceFile(className);
  Writer writer = jfo.openWriter();
  javaFile.writeTo(writer);
  writer.flush();
} catch (FilerException e) {
  return Optional.of(typeSpec);
} catch (IOException e) {
  logger().warn(...);
}
```

The `Writer` is `flush()`-ed but never `close()`-d.

- The real `javax.annotation.processing.Filer` implementation in
  OpenJDK tolerates this: the file object is finalised at round end
  and the content becomes visible.
- `com.google.testing.compile.InMemoryJavaFileManager` does not. It
  publishes the written content to the in-memory backing store only
  when the writer is closed; until then `openInputStream()` /
  `openReader()` on the same `JavaFileObject` throw
  `FileNotFoundException`.

`writeFunctionalInterface(...)` reaches the same path through
`writeDefinedClass(...)`, so the fix lands in one place.

## Fix

Wrap the writer in try-with-resources so `close()` is always called,
including on the exceptional path through `JavaFile.writeTo(...)`:

```java
try {
  JavaFileObject jfo = filer.createSourceFile(className);
  try (Writer writer = jfo.openWriter()) {
    javaFile.writeTo(writer);
  }
} catch (FilerException e) {
  return Optional.of(typeSpec);
} catch (IOException e) {
  logger().warn("Could not write generated source file {}", className, e);
}
return Optional.of(typeSpec);
```

Keep:

- the early `return Optional.of(typeSpec)` on `FilerException`,
- the existing IOException log path,
- the return value contract (`Optional<TypeSpec>` always present).

Do NOT remove `writer.flush()` separately — try-with-resources calls
`close()` which performs the flush automatically.

## Regression test

Add a compile-testing-based test that fails on `00.10.00` and passes
after the fix. Two reasonable shapes:

1. **Self-contained smoke test** in `proxybuilder` itself: define a
   throwaway trigger annotation (e.g. `@SmokeProxy`) + a trivial
   subprocessor that emits a one-method wrapper, then assert with

   ```java
   Compilation result = Compiler.javac()
       .withProcessors(new SmokeProxyAnnotationProcessor())
       .compile(JavaFileObjects.forSourceLines("test.Foo", ...));
   assertThat(result).succeeded();
   assertThat(result)
       .generatedSourceFile("test.FooSmokeProxy")
       .contentsAsUtf8String()
       .contains("public void op()");
   ```

   That `.contentsAsUtf8String()` call is the line that throws on the
   unfixed code.

2. **Minimal-impact test** if you prefer not to ship a throwaway
   processor: use `compile-testing` against one of the already-shipped
   subprocessors (e.g. `StaticLoggingProxyAnnotationProcessor`). Same
   shape, fewer test fixtures.

Add `com.google.testing.compile:compile-testing:0.21.0` as a
`<scope>test</scope>` dependency if not already present.

## Verification checklist

- [ ] `mvn -q test` green on JDK 26.
- [ ] New test passes after the fix and fails (with
      `FileNotFoundException`) before the fix.
- [ ] No public-API signature changes.
- [ ] `writeFunctionalInterface(...)` still works (its file is also
      written through `writeDefinedClass`).
- [ ] CHANGELOG / release-notes entry for `00.10.01` mentions
      "fix: close generated-source writer so
       com.google.testing.compile can read its content".

## Constraints

- No CGLIB, ByteBuddy, or other bytecode tooling — keep proxybuilder
  JDK-only.
- No formatter/license-header churn outside the touched files.
- One commit, message style: `fix(BasicAnnotationProcessor): close
  source writer so InMemoryJavaFileManager publishes content`.
- No `Co-Authored-By:` footer, no "Generated with …" footer.
