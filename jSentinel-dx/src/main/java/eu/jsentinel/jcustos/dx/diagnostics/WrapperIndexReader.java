/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.diagnostics;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads the generated-wrappers index emitted by {@code jSentinel-processor}
 * into a {@link JSentinelProcessorReport}. The index lives at
 * {@code META-INF/jsentinel/generated-wrappers.idx} on the
 * classpath; each non-blank, non-comment line follows the format:
 *
 * <pre>
 *   sourceFqn:generatedFqn:processor:proxyBuilderVersion:method1,method2,...
 * </pre>
 *
 * <p>The reader does NOT scan arbitrary classes. The processor owns the
 * authoritative view; the reader merely surfaces it.
 * <p>The reader path shipped in V00.72; the corresponding writer in
 * {@code jSentinel-processor} shipped in V00.73. The reader returns an empty
 * report when no index file is on the classpath (e.g. a module that does not
 * use the processor, or a hand-authored index).
 *
 * @since 00.72.00
 */
final class WrapperIndexReader {

  static final String RESOURCE_PATH = WrapperIndexFormat.RESOURCE_PATH;

  private WrapperIndexReader() {
  }

  /**
   * @return the merged processor report from every visible index file
   *         on the given class loader.
   */
  static JSentinelProcessorReport read(ClassLoader cl) {
    if (cl == null) {
      return JSentinelProcessorReport.empty();
    }

    List<GeneratedJSentinelWrapper> wrappers = new ArrayList<>();
    List<ProcessorWarning> warnings = new ArrayList<>();
    Set<String> seenKeys = new LinkedHashSet<>();

    Enumeration<URL> indexResources;
    try {
      indexResources = cl.getResources(WrapperIndexFormat.RESOURCE_PATH);
    } catch (IOException io) {
      warnings.add(new ProcessorWarning(
          "processor/index-malformed",
          "Failed to enumerate generated-wrappers.idx: " + io.getMessage(),
          "Inspect the jSentinel-processor build configuration."));
      return new JSentinelProcessorReport(wrappers, warnings);
    }

    while (indexResources.hasMoreElements()) {
      URL url = indexResources.nextElement();
      try (InputStream in = url.openStream();
           BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
        String line;
        while ((line = r.readLine()) != null) {
          if (line.isBlank() || line.startsWith("#")) {
            continue;
          }
          parseLine(line.trim(), wrappers, warnings, seenKeys, cl, url.toString());
        }
      } catch (IOException io) {
        warnings.add(new ProcessorWarning(
            "processor/index-malformed",
            "Failed to read " + url + ": " + io.getMessage(),
            "Inspect the jSentinel-processor build configuration."));
      }
    }
    return new JSentinelProcessorReport(wrappers, warnings);
  }

  private static void parseLine(String line,
                                List<GeneratedJSentinelWrapper> wrappers,
                                List<ProcessorWarning> warnings,
                                Set<String> seenKeys,
                                ClassLoader cl,
                                String sourceUrl) {
    // sourceFqn:generatedFqn:processor:proxyBuilderVersion:method1,method2,...[:kind]
    // V00.74 added the optional sixth field `kind` (`secured` / `propagating`).
    // V00.73 lines without the sixth field default to SECURED.
    String[] parts = line.split(WrapperIndexFormat.FIELD_SEPARATOR, 6);
    if (parts.length < 5) {
      warnings.add(new ProcessorWarning(
          "processor/index-malformed",
          "Malformed index line in " + sourceUrl + ": " + line,
          "Each entry must have at least 5 colon-separated fields."));
      return;
    }
    String sourceFqn = parts[0].trim();
    String generatedFqn = parts[1].trim();
    String processor = parts[2].trim();
    String version = parts[3].trim();
    List<String> methods = parts[4].isBlank()
        ? Collections.emptyList()
        : new ArrayList<>(Arrays.asList(parts[4].split(WrapperIndexFormat.METHOD_SEPARATOR)));
    methods.replaceAll(String::trim);
    GeneratedJSentinelWrapper.Kind kind = parseKind(parts, sourceUrl, line, warnings);

    String key = sourceFqn + "|" + generatedFqn;
    if (!seenKeys.add(key)) {
      return; // deterministic dedup
    }

    Class<?> sourceType = loadOrNull(cl, sourceFqn, warnings);
    Class<?> generatedType = loadOrNull(cl, generatedFqn, warnings);

    if (sourceType == null) {
      warnings.add(new ProcessorWarning(
          "secured-without-wrapper",
          "Indexed source type not loadable: " + sourceFqn,
          fixSnippet()));
      return;
    }
    if (generatedType == null) {
      warnings.add(new ProcessorWarning(
          "processor/wrapper-not-loadable",
          "Indexed wrapper type not loadable: " + generatedFqn
              + " (source: " + sourceFqn + ")",
          fixSnippet()));
      return;
    }

    String expectedSuffix = kind == GeneratedJSentinelWrapper.Kind.PROPAGATING
        ? "Propagating" : "Secured";
    String expectedWrapperFqn = sourceFqn + expectedSuffix;
    if (!expectedWrapperFqn.equals(generatedFqn)) {
      warnings.add(new ProcessorWarning(
          "secured-without-wrapper",
          "Indexed wrapper " + generatedFqn + " does not match the expected "
              + expectedWrapperFqn + " for source " + sourceFqn,
          fixSnippet()));
    }

    wrappers.add(new GeneratedJSentinelWrapper(
        sourceType, generatedType, processor, version, methods, kind));
  }

  private static GeneratedJSentinelWrapper.Kind parseKind(String[] parts,
                                                          String sourceUrl,
                                                          String line,
                                                          List<ProcessorWarning> warnings) {
    if (parts.length < 6 || parts[5] == null || parts[5].isBlank()) {
      return GeneratedJSentinelWrapper.Kind.SECURED;
    }
    String raw = parts[5].trim();
    if (WrapperIndexFormat.KIND_PROPAGATING.equals(raw)) {
      return GeneratedJSentinelWrapper.Kind.PROPAGATING;
    }
    if (WrapperIndexFormat.KIND_SECURED.equals(raw)) {
      return GeneratedJSentinelWrapper.Kind.SECURED;
    }
    warnings.add(new ProcessorWarning(
        "processor/index-malformed",
        "Unknown wrapper kind '" + raw + "' in " + sourceUrl + ": " + line,
        "Use 'secured' or 'propagating' as the sixth field; defaulting to SECURED."));
    return GeneratedJSentinelWrapper.Kind.SECURED;
  }

  private static Class<?> loadOrNull(ClassLoader cl, String fqn, List<ProcessorWarning> warnings) {
    try {
      return Class.forName(fqn, false, cl);
    } catch (ClassNotFoundException | LinkageError e) {
      return null;
    }
  }

  private static String fixSnippet() {
    return "Add jSentinel-processor to <annotationProcessorPaths>:\n"
        + "  <path>\n"
        + "    <groupId>eu.jsentinel.jcustos</groupId>\n"
        + "    <artifactId>jSentinel-processor</artifactId>\n"
        + "    <version>${jsentinel.version}</version>\n"
        + "  </path>";
  }

  /** Test-only helper exposing the resource path. */
  static Map<String, Object> internalsForTesting() {
    return Map.of("path", RESOURCE_PATH);
  }
}
