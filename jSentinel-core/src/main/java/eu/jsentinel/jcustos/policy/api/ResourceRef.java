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
package eu.jsentinel.jcustos.policy.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

/**
 * Stable reference to a concrete protected resource — the domain
 * object an admission rule wants to reason about (a document, a user,
 * a project, …).
 * <p>
 * {@code ResourceRef} is orthogonal to
 * {@link eu.jsentinel.jcustos.authorization.navigation.AccessContext#resourceType()
 * AccessContext.resourceType}, which describes the adapter-level
 * surface (REST endpoint, Vaadin view) rather than the domain entity.
 * Adapters set a {@code ResourceRef} into the inbound
 * {@code AccessContext} attributes under the key
 * {@link #ATTRIBUTE_KEY}; {@code RequiresPolicyEvaluator} promotes it
 * into the {@code PolicyContext} so {@code ResourcePredicates} can
 * read it.
 *
 * <p>A {@link TenantId} component carries the tenant scope of the
 * resource. Single-tenant applications never need to pass it: the
 * two-argument convenience constructor implicitly uses
 * {@link TenantId#DEFAULT}, so {@code new ResourceRef("document", "42")}
 * keeps working without changes.
 *
 * @param resourceType non-blank resource type (e.g. {@code "document"})
 * @param resourceId   non-blank resource identifier (e.g. {@code "42"})
 * @param tenant       tenant scope of the resource; {@code null} is
 *                     normalised to {@link TenantId#DEFAULT}
 */
@ExperimentalJSentinelApi
public record ResourceRef(String resourceType, String resourceId, TenantId tenant) {

  /**
   * Key under which adapters / callers stash a {@code ResourceRef}
   * in {@code AccessContext.attributes()} so the
   * {@code RequiresPolicyEvaluator} can promote it into the
   * {@code PolicyContext}.
   */
  public static final String ATTRIBUTE_KEY = "resourceRef";

  /**
   * Validates the record components and substitutes
   * {@link TenantId#DEFAULT} for a {@code null} tenant.
   *
   * @param resourceType non-blank resource type
   * @param resourceId   non-blank resource identifier
   * @param tenant       tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
   */
  public ResourceRef {
    if (resourceType == null || resourceType.isBlank()) {
      throw new IllegalArgumentException("resourceType must not be blank");
    }
    if (resourceId == null || resourceId.isBlank()) {
      throw new IllegalArgumentException("resourceId must not be blank");
    }
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
  }

  /**
   * Convenience constructor for single-tenant call sites: implicitly
   * targets {@link TenantId#DEFAULT}.
   *
   * @param resourceType non-blank resource type
   * @param resourceId   non-blank resource identifier
   */
  public ResourceRef(String resourceType, String resourceId) {
    this(resourceType, resourceId, TenantId.DEFAULT);
  }
}
