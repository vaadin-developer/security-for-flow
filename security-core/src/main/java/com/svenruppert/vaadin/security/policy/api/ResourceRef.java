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
package com.svenruppert.vaadin.security.policy.api;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

/**
 * Stable reference to a concrete protected resource — the domain
 * object an admission rule wants to reason about (a document, a user,
 * a project, …).
 * <p>
 * {@code ResourceRef} is orthogonal to
 * {@link com.svenruppert.vaadin.security.authorization.navigation.AccessContext#resourceType()
 * AccessContext.resourceType}, which describes the adapter-level
 * surface (REST endpoint, Vaadin view) rather than the domain entity.
 * Adapters set a {@code ResourceRef} into the inbound
 * {@code AccessContext} attributes under the key
 * {@link #ATTRIBUTE_KEY}; {@code RequiresPolicyEvaluator} promotes it
 * into the {@code PolicyContext} so {@code ResourcePredicates} can
 * read it.
 *
 * @param resourceType non-blank resource type (e.g. {@code "document"})
 * @param resourceId   non-blank resource identifier (e.g. {@code "42"})
 */
@ExperimentalSecurityApi
public record ResourceRef(String resourceType, String resourceId) {

  /**
   * Key under which adapters / callers stash a {@code ResourceRef}
   * in {@code AccessContext.attributes()} so the
   * {@code RequiresPolicyEvaluator} can promote it into the
   * {@code PolicyContext}.
   */
  public static final String ATTRIBUTE_KEY = "resourceRef";

  /**
   * Validates the record components.
   *
   * @param resourceType non-blank resource type
   * @param resourceId   non-blank resource identifier
   */
  public ResourceRef {
    if (resourceType == null || resourceType.isBlank()) {
      throw new IllegalArgumentException("resourceType must not be blank");
    }
    if (resourceId == null || resourceId.isBlank()) {
      throw new IllegalArgumentException("resourceId must not be blank");
    }
  }
}
