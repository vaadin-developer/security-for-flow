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

import java.util.List;

/**
 * Immutable snapshot of the OpenAPI document metadata collected by
 * {@link RestOpenApiMetadataBuilder}. Published via
 * {@link RestOpenApiContext}; the
 * {@code OpenApiSecurityMetadataGenerator} consumes it as the
 * Info-object inputs for the generated document.
 *
 * @param title       Info.title; may be {@code null}
 * @param version     Info.version; may be {@code null}
 * @param description Info.description; may be {@code null}
 * @param servers     Server URLs; never {@code null} (may be empty)
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public record RestOpenApiMetadata(
    String title,
    String version,
    String description,
    List<String> servers
) {

  /** Defensive copies on construction. */
  public RestOpenApiMetadata {
    servers = List.copyOf(servers);
  }
}
