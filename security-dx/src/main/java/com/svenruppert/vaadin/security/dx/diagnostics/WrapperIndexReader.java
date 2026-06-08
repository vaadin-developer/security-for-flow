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
package com.svenruppert.vaadin.security.dx.diagnostics;

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
 * Reads the generated-wrappers index emitted by {@code security-processor}
 * into a {@link SecurityProcessorReport}. The index lives at
 * {@code META-INF/security-for-flow/generated-wrappers.idx} on the
 * classpath; each non-blank, non-comment line follows the format:
 *
 * <pre>
 *   sourceFqn:generatedFqn:processor:proxyBuilderVersion:method1,method2,...
 * </pre>
 *
 * <p>The reader does NOT scan arbitrary classes. The processor owns the
 * authoritative view; the reader merely surfaces it.
 * <p>V00.72 ships only the reader path. The corresponding writer in
 * {@code security-processor} is staged as a V00.73 follow-up so that
 * the V00.72 invariant "behaviour of security-processor unchanged"
 * holds. Until then, the reader returns an empty report unless a
 * consumer ships a hand-authored index file.
 *
 * @since 00.72.00
 */
final class WrapperIndexReader {

  static final String RESOURCE_PATH = "META-INF/security-for-flow/generated-wrappers.idx";

  private WrapperIndexReader() {
  }

  /**
   * @return the merged processor report from every visible index file
   *         on the given class loader.
   */
  static SecurityProcessorReport read(ClassLoader cl) {
    if (cl == null) {
      return SecurityProcessorReport.empty();
    }

    List<GeneratedSecurityWrapper> wrappers = new ArrayList<>();
    List<ProcessorWarning> warnings = new ArrayList<>();
    Set<String> seenKeys = new LinkedHashSet<>();

    Enumeration<URL> indexResources;
    try {
      indexResources = cl.getResources(RESOURCE_PATH);
    } catch (IOException io) {
      warnings.add(new ProcessorWarning(
          "processor/index-malformed",
          "Failed to enumerate generated-wrappers.idx: " + io.getMessage(),
          "Inspect the security-processor build configuration."));
      return new SecurityProcessorReport(wrappers, warnings);
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
            "Inspect the security-processor build configuration."));
      }
    }
    return new SecurityProcessorReport(wrappers, warnings);
  }

  private static void parseLine(String line,
                                List<GeneratedSecurityWrapper> wrappers,
                                List<ProcessorWarning> warnings,
                                Set<String> seenKeys,
                                ClassLoader cl,
                                String sourceUrl) {
    // sourceFqn:generatedFqn:processor:proxyBuilderVersion:method1,method2,...
    String[] parts = line.split(":", 5);
    if (parts.length < 5) {
      warnings.add(new ProcessorWarning(
          "processor/index-malformed",
          "Malformed index line in " + sourceUrl + ": " + line,
          "Each entry must have 5 colon-separated fields."));
      return;
    }
    String sourceFqn = parts[0].trim();
    String generatedFqn = parts[1].trim();
    String processor = parts[2].trim();
    String version = parts[3].trim();
    List<String> methods = parts[4].isBlank()
        ? Collections.emptyList()
        : new ArrayList<>(Arrays.asList(parts[4].split(",")));
    methods.replaceAll(String::trim);

    String key = sourceFqn + "|" + generatedFqn;
    if (!seenKeys.add(key)) {
      return; // deterministic dedup
    }

    Class<?> sourceType = loadOrNull(cl, sourceFqn, warnings);
    Class<?> generatedType = loadOrNull(cl, generatedFqn, warnings);

    if (sourceType == null) {
      warnings.add(new ProcessorWarning(
          "secured-without-wrapper",
          "Indexed @Secured source type not loadable: " + sourceFqn,
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

    String expectedWrapperFqn = sourceFqn + "Secured";
    if (!expectedWrapperFqn.equals(generatedFqn)) {
      warnings.add(new ProcessorWarning(
          "secured-without-wrapper",
          "Indexed wrapper " + generatedFqn + " does not match the expected "
              + expectedWrapperFqn + " for source " + sourceFqn,
          fixSnippet()));
    }

    wrappers.add(new GeneratedSecurityWrapper(
        sourceType, generatedType, processor, version, methods));
  }

  private static Class<?> loadOrNull(ClassLoader cl, String fqn, List<ProcessorWarning> warnings) {
    try {
      return Class.forName(fqn, false, cl);
    } catch (ClassNotFoundException | LinkageError e) {
      return null;
    }
  }

  private static String fixSnippet() {
    return "Add security-processor to <annotationProcessorPaths>:\n"
        + "  <path>\n"
        + "    <groupId>com.svenruppert</groupId>\n"
        + "    <artifactId>security-processor</artifactId>\n"
        + "    <version>${security-for-flow.version}</version>\n"
        + "  </path>";
  }

  /** Test-only helper exposing the resource path. */
  static Map<String, Object> internalsForTesting() {
    return Map.of("path", RESOURCE_PATH);
  }
}
