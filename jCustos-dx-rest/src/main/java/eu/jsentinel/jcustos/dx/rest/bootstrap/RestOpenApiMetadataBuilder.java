/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
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
package eu.jsentinel.jcustos.dx.rest.bootstrap;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Fluent sub-builder for {@link RestOpenApiMetadata}. Created via
 * {@code RestJCustosBootstrap.openApiMetadata(consumer)}.
 *
 * <pre>
 *   RestSecurity.bootstrap()
 *       .openApiMetadata(o -> o
 *           .title("Demo REST API")
 *           .version("0.74.0")
 *           .description("Demo endpoints secured by jCustos.")
 *           .servers("https://api.example.com"))
 *       .install();
 * </pre>
 *
 * @since 00.74.00
 */
public final class RestOpenApiMetadataBuilder {

  private String title;
  private String version;
  private String description;
  private final List<String> servers = new ArrayList<>();

  RestOpenApiMetadataBuilder() {
  }

  /**
   * Sets the {@code Info.title}.
   *
   * @param title non-blank title
   * @return this builder
   */
  public RestOpenApiMetadataBuilder title(String title) {
    this.title = requireNonBlank(title, "title");
    return this;
  }

  /**
   * Sets the {@code Info.version}.
   *
   * @param version non-blank version
   * @return this builder
   */
  public RestOpenApiMetadataBuilder version(String version) {
    this.version = requireNonBlank(version, "version");
    return this;
  }

  /**
   * Sets the {@code Info.description}.
   *
   * @param description non-null description (may be empty)
   * @return this builder
   */
  public RestOpenApiMetadataBuilder description(String description) {
    this.description = Objects.requireNonNull(description, "description");
    return this;
  }

  /**
   * Replaces the {@code servers[]} list (each item is a server URL).
   *
   * @param urls server URLs; non-null
   * @return this builder
   */
  public RestOpenApiMetadataBuilder servers(String... urls) {
    Objects.requireNonNull(urls, "urls");
    servers.clear();
    servers.addAll(Arrays.asList(urls));
    return this;
  }

  RestOpenApiMetadata toMetadata() {
    return new RestOpenApiMetadata(title, version, description, servers);
  }

  private static String requireNonBlank(String s, String name) {
    Objects.requireNonNull(s, name);
    if (s.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return s;
  }
}
