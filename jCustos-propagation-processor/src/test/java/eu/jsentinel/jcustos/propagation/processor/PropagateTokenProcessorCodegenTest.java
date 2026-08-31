/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.propagation.processor;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R17 (V00.76.10): the wrapper generator must emit <em>compilable</em> overrides
 * for generic-typed, varargs, overloaded and bounded-generic methods. The old
 * generator emitted {@code T.class} for a type-variable parameter and dropped the
 * method's type parameters, breaking the consuming build. This test runs the
 * real processor in-process and asserts the generated {@code DemoPropagating}
 * compiles with no errors.
 */
@DisplayName("PropagateTokenProcessor — generated code compiles for hard method shapes")
class PropagateTokenProcessorCodegenTest {

  private static final String SOURCE = """
      package demo;
      import eu.jsentinel.jcustos.annotations.PropagateToken;
      import java.util.List;
      public class Demo {
        @PropagateToken(audience = "svc")
        public <T> T echo(T value) { return value; }
        @PropagateToken
        public void send(String... parts) { }
        @PropagateToken
        public void op(String s) { }
        @PropagateToken
        public void op(int i) { }
        @PropagateToken
        public <N extends Number> N sum(N a, N b) { return a; }
        @PropagateToken
        public List<String> names(List<String> in) { return in; }
      }
      """;

  @Test
  @DisplayName("generic / varargs / overloaded / bounded-generic / parameterized methods generate compilable overrides")
  void hardMethodShapesCompile() throws IOException {
    JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    assertNotNull(compiler, "a JDK (not just a JRE) is required to run the annotation processor test");

    Path out = Files.createTempDirectory("prop-codegen-out");
    Path genSrc = Files.createTempDirectory("prop-codegen-gen");
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();

    try (StandardJavaFileManager fm = compiler.getStandardFileManager(diagnostics, null, null)) {
      fm.setLocationFromPaths(StandardLocation.CLASS_OUTPUT, List.of(out));
      fm.setLocationFromPaths(StandardLocation.SOURCE_OUTPUT, List.of(genSrc));

      JavaFileObject source = new SimpleJavaFileObject(
          URI.create("string:///demo/Demo.java"), JavaFileObject.Kind.SOURCE) {
        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
          return SOURCE;
        }
      };

      // Inherit this test JVM's classpath so jCustos-core (OutboundCall,
      // HeaderValue, PropagateTokenAdvisor, JCustosServiceResolver, the
      // @PropagateToken annotation, ...) is visible to both the source and the
      // generated DemoPropagating.
      List<String> options = List.of("-classpath", System.getProperty("java.class.path"));

      JavaCompiler.CompilationTask task = compiler.getTask(
          null, fm, diagnostics, options, null, List.of(source));
      task.setProcessors(List.of(new PropagateTokenProcessor()));

      boolean ok = task.call();

      String errors = diagnostics.getDiagnostics().stream()
          .filter(d -> d.getKind() == Diagnostic.Kind.ERROR)
          .map(Object::toString)
          .reduce("", (a, b) -> a + "\n" + b);

      assertTrue(ok, "compilation (including the generated DemoPropagating) must succeed; errors:" + errors);
      assertTrue(Files.exists(out.resolve("demo/DemoPropagating.class")),
          "the generated DemoPropagating must have been produced and compiled");
    }
  }
}
