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
package com.svenruppert.jsentinel.autoservice.processor;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tiny harness around the JDK in-memory {@link JavaCompiler} used by the
 * processor tests. Compiles a set of named source files with the
 * {@link JSentinelAutoServiceProcessor} attached and captures the resulting
 * generated resources plus all compiler diagnostics.
 */
final class InMemoryCompiler {

  static final class Result {
    final boolean success;
    final List<Diagnostic<? extends JavaFileObject>> diagnostics;
    final Map<String, byte[]> generatedResources;

    Result(boolean success,
           List<Diagnostic<? extends JavaFileObject>> diagnostics,
           Map<String, byte[]> generatedResources) {
      this.success = success;
      this.diagnostics = diagnostics;
      this.generatedResources = generatedResources;
    }

    String resourceAsString(String relativePath) {
      byte[] bytes = generatedResources.get(relativePath);
      return bytes == null ? null : new String(bytes, StandardCharsets.UTF_8);
    }
  }

  /**
   * Compiles {@code sources} (map of FQN → source text) with the
   * processor under test.
   */
  static Result compile(Map<String, String> sources) throws IOException {
    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    DiagnosticCollector<JavaFileObject> collector = new DiagnosticCollector<>();
    StandardJavaFileManager std = javac.getStandardFileManager(collector, null, StandardCharsets.UTF_8);

    List<JavaFileObject> compilationUnits = new ArrayList<>();
    for (Map.Entry<String, String> e : sources.entrySet()) {
      compilationUnits.add(new InMemorySource(e.getKey(), e.getValue()));
    }

    Map<String, byte[]> resources = new LinkedHashMap<>();
    CapturingFileManager fm = new CapturingFileManager(std, resources);

    JavaCompiler.CompilationTask task = javac.getTask(
        null, fm, collector, List.of("-proc:full"), null, compilationUnits);
    task.setProcessors(List.of(new JSentinelAutoServiceProcessor()));
    boolean ok = task.call();
    fm.close();
    return new Result(ok, collector.getDiagnostics(), resources);
  }

  private static final class InMemorySource extends SimpleJavaFileObject {
    private final String code;

    InMemorySource(String fqn, String code) {
      super(URI.create("string:///" + fqn.replace('.', '/') + ".java"), Kind.SOURCE);
      this.code = code;
    }

    @Override
    public CharSequence getCharContent(boolean ignoreEncodingErrors) {
      return code;
    }
  }

  private static final class CapturingFileManager
      extends ForwardingJavaFileManager<StandardJavaFileManager> {
    private final Map<String, byte[]> resources;

    CapturingFileManager(StandardJavaFileManager delegate, Map<String, byte[]> resources) {
      super(delegate);
      this.resources = resources;
    }

    @Override
    public FileObject getFileForOutput(Location location, String packageName,
                                       String relativeName, FileObject sibling) {
      if (location == StandardLocation.CLASS_OUTPUT) {
        String path = packageName.isEmpty() ? relativeName : packageName.replace('.', '/') + '/' + relativeName;
        return new CapturingFileObject(path, resources);
      }
      try {
        return super.getFileForOutput(location, packageName, relativeName, sibling);
      } catch (IOException io) {
        throw new RuntimeException(io);
      }
    }

    @Override
    public FileObject getFileForInput(Location location, String packageName, String relativeName)
        throws IOException {
      if (location == StandardLocation.CLASS_OUTPUT) {
        String path = packageName.isEmpty() ? relativeName : packageName.replace('.', '/') + '/' + relativeName;
        byte[] bytes = resources.get(path);
        if (bytes == null) {
          throw new IOException("not found: " + path);
        }
        return new ReadOnlyResource(path, bytes);
      }
      return super.getFileForInput(location, packageName, relativeName);
    }
  }

  private static final class CapturingFileObject extends SimpleJavaFileObject {
    private final String path;
    private final Map<String, byte[]> resources;

    CapturingFileObject(String path, Map<String, byte[]> resources) {
      super(URI.create("mem:///" + path), Kind.OTHER);
      this.path = path;
      this.resources = resources;
    }

    @Override
    public OutputStream openOutputStream() {
      return new ByteArrayOutputStream() {
        @Override
        public void close() {
          resources.put(path, this.toByteArray());
        }
      };
    }
  }

  private static final class ReadOnlyResource extends SimpleJavaFileObject {
    private final byte[] bytes;

    ReadOnlyResource(String path, byte[] bytes) {
      super(URI.create("mem:///" + path), Kind.OTHER);
      this.bytes = bytes;
    }

    @Override
    public java.io.InputStream openInputStream() {
      return new java.io.ByteArrayInputStream(bytes);
    }

    @Override
    public CharSequence getCharContent(boolean ignoreEncodingErrors) {
      return new String(bytes, StandardCharsets.UTF_8);
    }
  }

  private InMemoryCompiler() {
  }
}
