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
package eu.jsentinel.jcustos.authorization.api.tenant;

/**
 * Identifier for the tenant scope of a security decision.
 * <p>
 * jCustos keeps multi-tenant support optional. Single-tenant
 * applications never need to think about {@code TenantId}: every
 * tenant-aware key, record, or context that ships in
 * {@code jCustos-core} carries {@link #DEFAULT} as a transparent
 * default, so existing single-tenant code keeps compiling and behaving
 * unchanged.
 *
 * <p>Multi-tenant applications opt in by:
 * <ul>
 *   <li>resolving the tenant of the inbound request (e.g. from a
 *       subdomain, a header, or the authenticated subject),</li>
 *   <li>constructing tenant-scoped keys / records explicitly with the
 *       resolved {@code TenantId}, and</li>
 *   <li>registering tenant-aware service implementations (stores,
 *       resolvers) through the usual SPI mechanism.</li>
 * </ul>
 *
 * <p>The {@code value} component is intentionally a free-form
 * {@code String} so applications can use whatever identifier shape
 * their persistence layer prefers (UUID, slug, opaque token). The
 * record only guarantees non-blank.
 *
 * @param value non-blank tenant identifier
 */
public record TenantId(String value) {

  /**
   * Sentinel tenant that single-tenant applications and tenant-unaware
   * call sites use without further configuration.
   */
  public static final TenantId DEFAULT = new TenantId("default");

  /**
   * Validates the record component.
   *
   * @param value non-blank tenant identifier
   */
  public TenantId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("value must not be blank");
    }
  }

  /**
   * Factory mirror of the canonical constructor — useful when readers
   * benefit from the explicit {@code TenantId.of("…")} shape, e.g. in
   * fluent builders.
   *
   * @param value non-blank tenant identifier
   * @return new {@code TenantId}
   */
  public static TenantId of(String value) {
    return new TenantId(value);
  }
}
