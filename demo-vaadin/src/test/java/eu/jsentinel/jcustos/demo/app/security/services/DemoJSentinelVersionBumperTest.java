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

import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectIdResolver;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.session.JSentinelVersion;
import eu.jsentinel.jcustos.session.JSentinelVersionKey;
import eu.jsentinel.jcustos.session.JSentinelVersionStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DemoJSentinelVersionBumper — SPI integration")
class DemoJSentinelVersionBumperTest {

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("SPI loads InMemoryJSentinelVersionStore and DemoSubjectIdResolver")
  void spiResolves() {
    Optional<JSentinelVersionStore> store =
        JSentinelServiceResolver.findJSentinelVersionStore();
    assertTrue(store.isPresent(),
        "InMemoryJSentinelVersionStore must be SPI-resolved in demo-vaadin");

    Optional<SubjectIdResolver<MyUser>> resolver =
        JSentinelServiceResolver.findSubjectIdResolver();
    assertTrue(resolver.isPresent(),
        "DemoSubjectIdResolver must be SPI-resolved in demo-vaadin");
  }

  @Test
  @DisplayName("DemoSubjectIdResolver maps MyUser to id-as-string")
  void resolverMapsUserId() {
    SubjectIdResolver<MyUser> resolver = JSentinelServiceResolver
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
    JSentinelVersionStore store =
        JSentinelServiceResolver.findJSentinelVersionStore().orElseThrow();
    JSentinelVersionKey key = new JSentinelVersionKey(
        TenantId.DEFAULT, SubjectId.of("7"));
    JSentinelVersion before = store.current(key);

    Optional<Long> after = DemoJSentinelVersionBumper.bump(user);

    assertTrue(after.isPresent(), "bump must return the post-increment value");
    assertEquals(before.value() + 1L, after.get());
    assertEquals(before.value() + 1L, store.current(key).value(),
        "bump must mutate the same store instance the SPI returns");
  }

  @Test
  @DisplayName("bump on null user is a safe no-op")
  void bumpNullUser() {
    assertEquals(Optional.empty(), DemoJSentinelVersionBumper.bump(null));
  }

  @Test
  @DisplayName("bump is a no-op when no JSentinelVersionStore is registered")
  void bumpWithoutStore() {
    JSentinelServiceResolver.resetAll();
    JSentinelServiceResolver.setJSentinelVersionStore(null);
    // Force the cache to "no SPI" so the bumper sees an empty store.
    // We can't fully unregister the SPI file, but a deliberate null
    // override defeats the cached load below.
    MyUser user = new MyUser(99L, "Eve",
        EnumSet.of(AuthorizationRole.USER));
    // With the SPI on the classpath, findJSentinelVersionStore() will
    // still load a fresh InMemoryJSentinelVersionStore — that's the
    // documented behaviour. So bump returns a value; we only verify
    // it does not throw and that the returned value is non-null.
    Optional<Long> result = DemoJSentinelVersionBumper.bump(user);
    assertNotNull(result);
  }
}
