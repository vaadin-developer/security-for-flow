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

import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ResourceAccessContext")
class ResourceAccessContextTest {

  private static final JSentinelSubject ALICE = new JSentinelSubject(
      "alice", "Alice", Set.of(), Set.of());

  private static AccessContext sampleAccessContext() {
    return new AccessContext(
        Optional.of(ALICE),
        "rest-endpoint",
        "/documents/42",
        "invoke",
        Map.of());
  }

  @Test
  @DisplayName("constructor rejects null accessContext")
  void rejectsNullAccessContext() {
    assertThrows(NullPointerException.class,
        () -> new ResourceAccessContext(null, new ResourceRef("document", "42")));
  }

  @Test
  @DisplayName("constructor rejects null resourceRef")
  void rejectsNullResourceRef() {
    assertThrows(NullPointerException.class,
        () -> new ResourceAccessContext(sampleAccessContext(), null));
  }

  @Test
  @DisplayName("records expose components verbatim")
  void exposesComponents() {
    AccessContext access = sampleAccessContext();
    ResourceRef ref = new ResourceRef("document", "42");
    ResourceAccessContext ctx = new ResourceAccessContext(access, ref);
    assertSame(access, ctx.accessContext());
    assertSame(ref, ctx.resourceRef());
  }

  @Test
  @DisplayName("subject() delegates to the wrapped AccessContext")
  void subjectDelegated() {
    ResourceAccessContext ctx = new ResourceAccessContext(
        sampleAccessContext(), new ResourceRef("document", "42"));
    assertTrue(ctx.subject().isPresent());
    assertEquals("alice", ctx.subject().orElseThrow().subjectId());
  }

  @Test
  @DisplayName("tenant() shortcut returns the ResourceRef's tenant")
  void tenantShortcutReadsResourceRef() {
    TenantId acme = new TenantId("acme");
    ResourceAccessContext ctx = new ResourceAccessContext(
        sampleAccessContext(),
        new ResourceRef("document", "42", acme));
    assertEquals(acme, ctx.tenant());
  }

  @Test
  @DisplayName("tenant() returns TenantId.DEFAULT for single-tenant ResourceRefs")
  void tenantShortcutDefault() {
    ResourceAccessContext ctx = new ResourceAccessContext(
        sampleAccessContext(),
        new ResourceRef("document", "42"));
    assertSame(TenantId.DEFAULT, ctx.tenant());
  }

  @Test
  @DisplayName("adapterResourceType() delegates to AccessContext.resourceType")
  void adapterResourceTypeDelegated() {
    ResourceAccessContext ctx = new ResourceAccessContext(
        sampleAccessContext(),
        new ResourceRef("document", "42"));
    assertEquals("rest-endpoint", ctx.adapterResourceType());
  }

  @Test
  @DisplayName("operation() delegates to AccessContext.operation")
  void operationDelegated() {
    ResourceAccessContext ctx = new ResourceAccessContext(
        sampleAccessContext(),
        new ResourceRef("document", "42"));
    assertEquals("invoke", ctx.operation());
  }
}
