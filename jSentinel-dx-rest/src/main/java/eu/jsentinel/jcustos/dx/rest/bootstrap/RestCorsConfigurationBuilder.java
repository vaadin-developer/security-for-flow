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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Fluent sub-builder for {@link RestCorsConfiguration}. Created by
 * {@code RestJSentinelBootstrap.cors(consumer)}; the consumer
 * receives the builder and configures origins, methods, headers,
 * exposed headers, credentials, and max-age.
 *
 * <pre>
 *   RestSecurity.bootstrap()
 *       .cors(c -> c
 *           .allowedOrigins("https://app.example.com")
 *           .allowedMethods("GET", "POST", "PUT", "DELETE")
 *           .allowCredentials(true)
 *           .maxAgeSeconds(3600))
 *       .install();
 * </pre>
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public final class RestCorsConfigurationBuilder {

  private final List<String> allowedOrigins = new ArrayList<>();
  private final List<String> allowedMethods = new ArrayList<>();
  private final List<String> allowedHeaders = new ArrayList<>();
  private final List<String> exposedHeaders = new ArrayList<>();
  private boolean allowCredentials;
  private long maxAgeSeconds = -1L;

  RestCorsConfigurationBuilder() {
  }

  /**
   * Replaces the allowed-origins list. {@code "*"} permits any
   * origin; combine with {@link #allowCredentials(boolean)} carefully
   * (browsers reject wildcard + credentials).
   *
   * @param origins origins; non-null, may be empty
   * @return this builder
   */
  public RestCorsConfigurationBuilder allowedOrigins(String... origins) {
    return replace(allowedOrigins, "origins", origins);
  }

  /**
   * Replaces the allowed-methods list (e.g. {@code "GET"}, {@code "POST"}).
   *
   * @param methods methods; non-null
   * @return this builder
   */
  public RestCorsConfigurationBuilder allowedMethods(String... methods) {
    return replace(allowedMethods, "methods", methods);
  }

  /**
   * Replaces the allowed-headers list (e.g. {@code "Authorization"},
   * {@code "Content-Type"}).
   *
   * @param headers headers; non-null
   * @return this builder
   */
  public RestCorsConfigurationBuilder allowedHeaders(String... headers) {
    return replace(allowedHeaders, "headers", headers);
  }

  /**
   * Replaces the exposed-headers list (response headers the browser
   * can read).
   *
   * @param headers headers; non-null
   * @return this builder
   */
  public RestCorsConfigurationBuilder exposedHeaders(String... headers) {
    return replace(exposedHeaders, "headers", headers);
  }

  /**
   * Emits {@code Access-Control-Allow-Credentials: true} when
   * {@code true}.
   *
   * @param allow {@code true} to allow credentials
   * @return this builder
   */
  public RestCorsConfigurationBuilder allowCredentials(boolean allow) {
    this.allowCredentials = allow;
    return this;
  }

  /**
   * Sets the preflight cache duration. Negative value suppresses
   * the {@code Access-Control-Max-Age} header.
   *
   * @param seconds duration in seconds, or {@code -1} to suppress
   * @return this builder
   */
  public RestCorsConfigurationBuilder maxAgeSeconds(long seconds) {
    this.maxAgeSeconds = seconds;
    return this;
  }

  RestCorsConfiguration toConfiguration() {
    return new RestCorsConfiguration(
        allowedOrigins, allowedMethods, allowedHeaders, exposedHeaders,
        allowCredentials, maxAgeSeconds);
  }

  private RestCorsConfigurationBuilder replace(List<String> target, String label, String[] values) {
    Objects.requireNonNull(values, label);
    target.clear();
    target.addAll(Arrays.asList(values));
    return this;
  }
}
