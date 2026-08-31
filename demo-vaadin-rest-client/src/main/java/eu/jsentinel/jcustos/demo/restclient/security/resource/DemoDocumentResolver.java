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
package eu.jsentinel.jcustos.demo.restclient.security.resource;

import eu.jsentinel.jcustos.policy.spi.ResourceResolver;

import java.util.Map;
import java.util.Optional;

/**
 * {@link ResourceResolver} for the {@code "document"} resource type
 * used by the Resource-Based Authorization demo. Looks up
 * {@link DemoDocument}s in the local {@link DemoDocumentStore} and
 * exposes the {@code ownerId} attribute that
 * {@code ResourcePredicates.ownerMatchesSubject(...)} consumes.
 */
public final class DemoDocumentResolver implements ResourceResolver<DemoDocument> {

  /** Resource type identifier. */
  public static final String RESOURCE_TYPE = "document";

  /** Attribute key used by the demo policy. */
  public static final String OWNER_ATTRIBUTE = "ownerId";

  @Override
  public String resourceType() {
    return RESOURCE_TYPE;
  }

  @Override
  public Optional<DemoDocument> resolve(String id) {
    return DemoDocumentStore.find(id);
  }

  @Override
  public Map<String, Object> attributes(DemoDocument resource) {
    return Map.of(
        OWNER_ATTRIBUTE, resource.ownerId(),
        "title", resource.title());
  }
}
