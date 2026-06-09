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

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.vaadin.security.authorization.api.JSentinelSubject;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;

import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Composite of an adapter-neutral {@link AccessContext} and the
 * concrete {@link ResourceRef} the request is about.
 * <p>
 * Java records cannot subclass each other, so {@code AccessContext}
 * cannot be extended with a {@code ResourceRef} component in place.
 * {@code ResourceAccessContext} solves the same problem by
 * <em>composition</em>: it wraps the existing {@code AccessContext} and
 * adds a non-null {@code ResourceRef} next to it.
 *
 * <p>Use cases:
 * <ul>
 *   <li>An adapter that always resolves a domain entity (e.g. a REST
 *       handler for {@code /documents/{id}}) builds a
 *       {@code ResourceAccessContext} once and threads it through
 *       application code, instead of stashing the {@code ResourceRef}
 *       into the inbound {@code AccessContext.attributes()} under the
 *       loosely-typed {@link ResourceRef#ATTRIBUTE_KEY} key.</li>
 *   <li>{@code RequiresPolicyEvaluator} keeps reading the attribute
 *       map for backwards compatibility, but new evaluators can take a
 *       {@code ResourceAccessContext} directly.</li>
 * </ul>
 *
 * <p>The tenant scope of the resource is exposed through the
 * {@link #tenant()} shortcut, which returns
 * {@code resourceRef.tenant()} — typically {@link TenantId#DEFAULT}
 * for single-tenant applications.
 *
 * @param accessContext adapter-neutral access context; must not be {@code null}
 * @param resourceRef   concrete domain resource the request targets; must not be {@code null}
 */
@ExperimentalJSentinelApi
public record ResourceAccessContext(
    AccessContext accessContext,
    ResourceRef resourceRef
) {

  /**
   * Validates the record components.
   *
   * @param accessContext adapter-neutral access context; non-null
   * @param resourceRef   concrete domain resource; non-null
   */
  public ResourceAccessContext {
    requireNonNull(accessContext, "accessContext must not be null");
    requireNonNull(resourceRef, "resourceRef must not be null");
  }

  /**
   * Shortcut to the authenticated subject of the wrapped access
   * context.
   *
   * @return authenticated subject, if any
   */
  public Optional<JSentinelSubject> subject() {
    return accessContext.subject();
  }

  /**
   * Shortcut to the tenant scope of the targeted resource.
   *
   * @return resource tenant, never {@code null}
   */
  public TenantId tenant() {
    return resourceRef.tenant();
  }

  /**
   * Shortcut to the adapter-level resource type
   * ({@code "vaadin-view"}, {@code "rest-endpoint"}, {@code "method"}).
   * Distinct from {@link ResourceRef#resourceType()}, which names the
   * domain entity type ({@code "document"}, {@code "project"}).
   *
   * @return adapter-level resource type
   */
  public String adapterResourceType() {
    return accessContext.resourceType();
  }

  /**
   * Shortcut to the requested operation
   * ({@code "navigate"}, {@code "invoke"}, ...).
   *
   * @return requested operation
   */
  public String operation() {
    return accessContext.operation();
  }
}
