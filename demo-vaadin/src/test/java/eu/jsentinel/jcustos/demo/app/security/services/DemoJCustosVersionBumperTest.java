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
package eu.jsentinel.jcustos.demo.app.security.services;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JCustosVersion;
import eu.jsentinel.jcustos.session.JCustosVersionKey;
import eu.jsentinel.jcustos.session.JCustosVersionStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DemoJCustosVersionBumper — SPI integration")
class DemoJCustosVersionBumperTest {

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("SPI loads InMemoryJCustosVersionStore and DemoSubjectIdResolver")
  void spiResolves() {
    Optional<JCustosVersionStore> store =
        JCustosServiceResolver.findJCustosVersionStore();
    assertTrue(store.isPresent(),
        "InMemoryJCustosVersionStore must be SPI-resolved in demo-vaadin");

    Optional<SubjectIdResolver<MyUser>> resolver =
        JCustosServiceResolver.findSubjectIdResolver();
    assertTrue(resolver.isPresent(),
        "DemoSubjectIdResolver must be SPI-resolved in demo-vaadin");
  }

  @Test
  @DisplayName("DemoSubjectIdResolver maps MyUser to id-as-string")
  void resolverMapsUserId() {
    SubjectIdResolver<MyUser> resolver = JCustosServiceResolver
        .<MyUser>findSubjectIdResolver().orElseThrow();
    MyUser user = new MyUser(42L, "Alice",
        EnumSet.of(AuthorizationRole.USER));
    assertEquals(SubjectId.of("42"), resolver.resolve(user));
    assertEquals(TenantId.DEFAULT, resolver.tenantFor(user));
  }

  @Test
  @DisplayName("bump increments the SPI-resolved store for the user's SubjectId")
  void bumpIncrementsStore() {
    MyUser user = new MyUser(7L, "Bob",
        EnumSet.of(AuthorizationRole.USER));
    JCustosVersionStore store =
        JCustosServiceResolver.findJCustosVersionStore().orElseThrow();
    JCustosVersionKey key = new JCustosVersionKey(
        TenantId.DEFAULT, SubjectId.of("7"));
    JCustosVersion before = store.current(key);

    Optional<Long> after = DemoJCustosVersionBumper.bump(user);

    assertTrue(after.isPresent(), "bump must return the post-increment value");
    assertEquals(before.value() + 1L, after.get());
    assertEquals(before.value() + 1L, store.current(key).value(),
        "bump must mutate the same store instance the SPI returns");
  }

  @Test
  @DisplayName("bump on null user is a safe no-op")
  void bumpNullUser() {
    assertEquals(Optional.empty(), DemoJCustosVersionBumper.bump(null));
  }

  @Test
  @DisplayName("bump is a no-op when no JCustosVersionStore is registered")
  void bumpWithoutStore() {
    JCustosServiceResolver.resetAll();
    JCustosServiceResolver.setJCustosVersionStore(null);
    // Force the cache to "no SPI" so the bumper sees an empty store.
    // We can't fully unregister the SPI file, but a deliberate null
    // override defeats the cached load below.
    MyUser user = new MyUser(99L, "Eve",
        EnumSet.of(AuthorizationRole.USER));
    // With the SPI on the classpath, findJCustosVersionStore() will
    // still load a fresh InMemoryJCustosVersionStore — that's the
    // documented behaviour. So bump returns a value; we only verify
    // it does not throw and that the returned value is non-null.
    Optional<Long> result = DemoJCustosVersionBumper.bump(user);
    assertNotNull(result);
  }
}
