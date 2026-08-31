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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ResourceRefTest {

  @Test
  @DisplayName("constructor rejects null resourceType")
  void rejectsNullResourceType() {
    assertThrows(IllegalArgumentException.class,
        () -> new ResourceRef(null, "42"));
  }

  @Test
  @DisplayName("constructor rejects blank resourceType")
  void rejectsBlankResourceType() {
    assertThrows(IllegalArgumentException.class,
        () -> new ResourceRef("", "42"));
    assertThrows(IllegalArgumentException.class,
        () -> new ResourceRef("   ", "42"));
  }

  @Test
  @DisplayName("constructor rejects null resourceId")
  void rejectsNullResourceId() {
    assertThrows(IllegalArgumentException.class,
        () -> new ResourceRef("document", null));
  }

  @Test
  @DisplayName("constructor rejects blank resourceId")
  void rejectsBlankResourceId() {
    assertThrows(IllegalArgumentException.class,
        () -> new ResourceRef("document", ""));
    assertThrows(IllegalArgumentException.class,
        () -> new ResourceRef("document", "   "));
  }

  @Test
  @DisplayName("records expose components verbatim")
  void recordExposesComponents() {
    ResourceRef ref = new ResourceRef("document", "42");
    assertEquals("document", ref.resourceType());
    assertEquals("42", ref.resourceId());
  }

  @Test
  @DisplayName("ATTRIBUTE_KEY is the documented constant")
  void attributeKeyIsStable() {
    assertEquals("resourceRef", ResourceRef.ATTRIBUTE_KEY);
  }

  // ── tenant component ─────────────────────────────────────────────

  @Test
  @DisplayName("two-arg constructor implicitly uses TenantId.DEFAULT")
  void twoArgConstructorUsesDefaultTenant() {
    ResourceRef ref = new ResourceRef("document", "42");
    assertSame(TenantId.DEFAULT, ref.tenant());
  }

  @Test
  @DisplayName("three-arg constructor keeps the supplied tenant")
  void threeArgConstructorKeepsTenant() {
    TenantId acme = new TenantId("acme");
    ResourceRef ref = new ResourceRef("document", "42", acme);
    assertEquals(acme, ref.tenant());
  }

  @Test
  @DisplayName("null tenant in the three-arg constructor is normalised to DEFAULT")
  void nullTenantNormalisedToDefault() {
    ResourceRef ref = new ResourceRef("document", "42", null);
    assertSame(TenantId.DEFAULT, ref.tenant());
  }

  @Test
  @DisplayName("equals considers the tenant component")
  void equalsConsidersTenant() {
    ResourceRef defaultScope = new ResourceRef("document", "42");
    ResourceRef acmeScope = new ResourceRef("document", "42", new TenantId("acme"));
    assertNotEquals(defaultScope, acmeScope,
        "same type+id in different tenants must not collide");
  }

  @Test
  @DisplayName("equals matches when two-arg and three-arg point at the default tenant")
  void twoArgEqualsThreeArgWithDefault() {
    ResourceRef shortForm = new ResourceRef("document", "42");
    ResourceRef explicitDefault =
        new ResourceRef("document", "42", TenantId.DEFAULT);
    assertEquals(shortForm, explicitDefault);
  }
}
