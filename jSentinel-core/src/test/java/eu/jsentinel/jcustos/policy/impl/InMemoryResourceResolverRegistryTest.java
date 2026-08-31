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
package eu.jsentinel.jcustos.policy.impl;

import eu.jsentinel.jcustos.policy.api.ResourceRef;
import eu.jsentinel.jcustos.policy.spi.ResourceResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryResourceResolverRegistryTest {

  @Test
  @DisplayName("register rejects null resolver")
  void registerRejectsNull() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    assertThrows(NullPointerException.class, () -> registry.register(null));
  }

  @Test
  @DisplayName("register rejects resolver with blank resourceType")
  void registerRejectsBlankResourceType() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    assertThrows(IllegalArgumentException.class,
        () -> registry.register(new BlankTypeResolver()));
  }

  @Test
  @DisplayName("find returns empty for null and unknown types")
  void findEmpty() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    assertTrue(registry.find(null).isEmpty());
    assertTrue(registry.find("nope").isEmpty());
  }

  @Test
  @DisplayName("register then find returns the registered resolver")
  void registerThenFind() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    DocumentResolver resolver = new DocumentResolver();
    registry.register(resolver);

    Optional<ResourceResolver<?>> found = registry.find("document");
    assertTrue(found.isPresent());
    assertSame(resolver, found.orElseThrow());
  }

  @Test
  @DisplayName("re-registering the same resourceType replaces the previous entry")
  void reRegisterReplaces() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    DocumentResolver first = new DocumentResolver();
    DocumentResolver second = new DocumentResolver();
    registry.register(first);
    registry.register(second);
    assertSame(second, registry.find("document").orElseThrow());
  }

  @Test
  @DisplayName("resolveAttributes rejects null ref")
  void resolveAttributesRejectsNullRef() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    assertThrows(NullPointerException.class, () -> registry.resolveAttributes(null));
  }

  @Test
  @DisplayName("resolveAttributes returns empty when no resolver is registered")
  void resolveAttributesUnknownType() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    assertTrue(registry.resolveAttributes(new ResourceRef("document", "42")).isEmpty());
  }

  @Test
  @DisplayName("resolveAttributes returns empty when the resolver does not know the id")
  void resolveAttributesUnknownId() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    registry.register(new DocumentResolver()); // empty store
    assertTrue(registry.resolveAttributes(new ResourceRef("document", "42")).isEmpty());
  }

  @Test
  @DisplayName("resolveAttributes returns the resolver's attribute map for known refs")
  void resolveAttributesHit() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    DocumentResolver resolver = new DocumentResolver();
    resolver.add("42", new Document("alice"));
    registry.register(resolver);

    Map<String, Object> attributes = registry.resolveAttributes(
        new ResourceRef("document", "42")).orElseThrow();
    assertEquals("alice", attributes.get("ownerId"));
  }

  @Test
  @DisplayName("resolveAttributes maps null resolver attributes to an empty map")
  void resolveAttributesNullAttributesBecomeEmptyMap() {
    InMemoryResourceResolverRegistry registry = new InMemoryResourceResolverRegistry();
    registry.register(new NullAttributesResolver());

    Map<String, Object> attributes = registry.resolveAttributes(
        new ResourceRef("noisy", "ignored")).orElseThrow();
    assertTrue(attributes.isEmpty());
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private record Document(String ownerId) {
  }

  private static final class DocumentResolver implements ResourceResolver<Document> {
    private final java.util.Map<String, Document> store = new java.util.HashMap<>();

    void add(String id, Document doc) {
      store.put(id, doc);
    }

    @Override
    public String resourceType() {
      return "document";
    }

    @Override
    public Optional<Document> resolve(String id) {
      return Optional.ofNullable(store.get(id));
    }

    @Override
    public Map<String, Object> attributes(Document resource) {
      return Map.of("ownerId", resource.ownerId());
    }
  }

  private static final class BlankTypeResolver implements ResourceResolver<Object> {
    @Override public String resourceType() { return "  "; }
    @Override public Optional<Object> resolve(String id) { return Optional.empty(); }
    @Override public Map<String, Object> attributes(Object resource) { return Map.of(); }
  }

  private static final class NullAttributesResolver implements ResourceResolver<Object> {
    @Override public String resourceType() { return "noisy"; }
    @Override public Optional<Object> resolve(String id) { return Optional.of(new Object()); }
    @Override public Map<String, Object> attributes(Object resource) { return null; }
  }
}
