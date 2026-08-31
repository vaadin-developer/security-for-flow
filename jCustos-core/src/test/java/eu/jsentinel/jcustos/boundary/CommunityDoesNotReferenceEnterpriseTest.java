package eu.jsentinel.jcustos.boundary;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Executable form of the open-core boundary: no community source may reach into
 * the commercial edition.
 *
 * <p>With the editions in separate repositories the compiler already enforces
 * this, but a compiler cannot see a {@code Class.forName("...")}, a service-file
 * entry or a configuration string. This test does, and it states the contract
 * where a reader will find it.
 *
 * <p>Prose is exempt on purpose. Javadoc legitimately records where code moved
 * from — {@code EnvelopeWireCodec} says it came from the REST/SSE bridge — and
 * failing on that would push authors to delete accurate history.
 */
class CommunityDoesNotReferenceEnterpriseTest {

  /**
   * Package prefixes owned by the enterprise edition. Deliberately precise:
   * {@code …jcustos.audit} and {@code …jcustos.events} are community packages,
   * only the listed sub-packages moved out.
   */
  private static final List<String> ENTERPRISE_PACKAGES = List.of(
      "eu.jsentinel.jcustos.monitoring",
      "eu.jsentinel.jcustos.audit.integrity",
      "eu.jsentinel.jcustos.events.otel",
      "eu.jsentinel.jcustos.events.persistence",
      "eu.jsentinel.jcustos.events.rest",
      "eu.jsentinel.jcustos.events.siem",
      "eu.jsentinel.jcustos.events.webhook");

  /** The enterprise Maven coordinate; a community pom or source must never name it. */
  private static final String ENTERPRISE_GROUP_ID = "eu.jsentinel.jcustos.enterprise";

  @Test
  @DisplayName("no community main source references an enterprise package")
  void noCommunitySourceReferencesEnterprise() throws IOException {
    Path reactorRoot = reactorRoot();
    List<String> violations = new ArrayList<>();

    try (Stream<Path> sources = Files.walk(reactorRoot)) {
      List<Path> mainSources = sources
          .filter(p -> p.toString().endsWith(".java"))
          .filter(p -> p.toString().contains("/src/main/java/"))
          .filter(p -> !p.toString().contains("/target/"))
          .toList();

      for (Path source : mainSources) {
        List<String> lines = Files.readAllLines(source);
        for (int i = 0; i < lines.size(); i++) {
          String line = lines.get(i);
          if (isComment(line)) {
            continue;
          }
          for (String forbidden : ENTERPRISE_PACKAGES) {
            if (line.contains(forbidden)) {
              violations.add(reactorRoot.relativize(source) + ":" + (i + 1) + " -> " + forbidden);
            }
          }
          if (line.contains(ENTERPRISE_GROUP_ID)) {
            violations.add(reactorRoot.relativize(source) + ":" + (i + 1) + " -> " + ENTERPRISE_GROUP_ID);
          }
        }
      }
    }

    assertTrue(violations.isEmpty(),
        () -> "Community sources must not reference the enterprise edition, but found:\n  "
            + String.join("\n  ", violations));
  }

  @Test
  @DisplayName("no community pom depends on an enterprise artifact")
  void noCommunityPomDependsOnEnterprise() throws IOException {
    Path reactorRoot = reactorRoot();
    List<String> violations = new ArrayList<>();

    try (Stream<Path> poms = Files.walk(reactorRoot)) {
      List<Path> files = poms
          .filter(p -> p.getFileName().toString().equals("pom.xml"))
          .filter(p -> !p.toString().contains("/target/"))
          .toList();

      for (Path pom : files) {
        String content = Files.readString(pom);
        if (content.contains("<groupId>" + ENTERPRISE_GROUP_ID + "</groupId>")) {
          violations.add(reactorRoot.relativize(pom).toString());
        }
      }
    }

    assertTrue(violations.isEmpty(),
        () -> "Community poms must not depend on enterprise artifacts, but found:\n  "
            + String.join("\n  ", violations));
  }

  private static boolean isComment(String line) {
    String trimmed = line.strip();
    return trimmed.startsWith("*") || trimmed.startsWith("//") || trimmed.startsWith("/*");
  }

  /** Walks up until the aggregator pom is found, so the test runs from any module. */
  private static Path reactorRoot() {
    Path candidate = Path.of("").toAbsolutePath();
    while (candidate != null) {
      Path pom = candidate.resolve("pom.xml");
      if (Files.exists(pom)) {
        try {
          if (Files.readString(pom).contains("<artifactId>jCustos-community-parent</artifactId>")
              && Files.readString(pom).contains("<modules>")) {
            return candidate;
          }
        } catch (IOException ignored) {
          // keep walking up
        }
      }
      candidate = candidate.getParent();
    }
    throw new IllegalStateException("community reactor root not found above " + Path.of("").toAbsolutePath());
  }
}
