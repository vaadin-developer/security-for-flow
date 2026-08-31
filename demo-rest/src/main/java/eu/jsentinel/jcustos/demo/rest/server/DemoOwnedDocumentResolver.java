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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.demo.rest.domain.DemoOwnedDocument;
import eu.jsentinel.jcustos.demo.rest.domain.DemoOwnedDocumentStore;
import eu.jsentinel.jcustos.policy.spi.ResourceResolver;

import java.util.Map;
import java.util.Optional;

/**
 * {@link ResourceResolver} for the {@code document} resource type.
 * Used by the V00.70 Policy-DSL example {@code document.owner-or-admin}
 * to fetch a document's {@code ownerId} attribute at policy
 * evaluation time.
 * <p>
 * Registered programmatically with the
 * {@code JCustosServiceResolver}'s
 * {@link eu.jsentinel.jcustos.policy.spi.ResourceResolverRegistry}
 * at {@code DemoRestServer} startup — no SPI file needed because
 * the resolver depends on a concrete store instance.
 */
public final class DemoOwnedDocumentResolver implements ResourceResolver<DemoOwnedDocument> {

  /** Resource type literal used everywhere — the @RequiresPolicy lookup, the resolver, the predicate. */
  public static final String RESOURCE_TYPE = "document";

  /** Attribute key the policy reads to compare against the subject id. */
  public static final String OWNER_ATTRIBUTE = "ownerId";

  private final DemoOwnedDocumentStore store;

  public DemoOwnedDocumentResolver(DemoOwnedDocumentStore store) {
    this.store = store;
  }

  @Override
  public String resourceType() {
    return RESOURCE_TYPE;
  }

  @Override
  public Optional<DemoOwnedDocument> resolve(String id) {
    if (id == null || id.isBlank()) {
      return Optional.empty();
    }
    try {
      return store.findById(Long.parseLong(id));
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
  }

  @Override
  public Map<String, Object> attributes(DemoOwnedDocument resource) {
    return Map.of(
        OWNER_ATTRIBUTE, resource.ownerId(),
        "id", resource.id(),
        "title", resource.title());
  }
}
