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
package com.svenruppert.vaadin.security.authorization.api;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SecurityServiceResolver")
class SecurityServiceResolverTest {

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
  }

  @Test
  @DisplayName("missing AuthenticationService SPI produces actionable error message")
  void missingAuthenticationService_throwsWithMessage() {
    // In a test environment without META-INF/services registration,
    // the resolver should throw with a clear, actionable message.
    var ex = assertThrows(IllegalStateException.class,
        SecurityServiceResolver::authenticationService);

    assertTrue(ex.getMessage().contains("AuthenticationService"),
        "Error message should mention the missing service type");
    assertTrue(ex.getMessage().contains("META-INF/services"),
        "Error message should mention META-INF/services registration");
  }

  @Test
  @DisplayName("findAuthenticationService returns empty when no SPI registered")
  void findAuthenticationService_empty() {
    var result = SecurityServiceResolver.findAuthenticationService();
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("multiple AuthenticationService implementations fail explicitly")
  void multipleAuthenticationServices_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> SecurityServiceResolver.requireSingleService(
            AuthenticationService.class,
            java.util.List.of(new FirstAuthenticationService(), new SecondAuthenticationService())));

    assertTrue(ex.getMessage().contains("multiple implementations"));
    assertTrue(ex.getMessage().contains(FirstAuthenticationService.class.getName()));
    assertTrue(ex.getMessage().contains(SecondAuthenticationService.class.getName()));
  }

  @Test
  @DisplayName("missing AuthorizationService SPI produces actionable error message")
  void missingAuthorizationService_throwsWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        SecurityServiceResolver::authorizationService);

    assertTrue(ex.getMessage().contains("AuthorizationService"),
        "Error message should mention the missing service type");
    assertTrue(ex.getMessage().contains("META-INF/services"),
        "Error message should mention META-INF/services registration");
  }

  @Test
  @DisplayName("findAuthorizationService returns empty when no SPI registered")
  void findAuthorizationService_empty() {
    var result = SecurityServiceResolver.findAuthorizationService();
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("multiple AuthorizationService implementations fail explicitly")
  void multipleAuthorizationServices_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> SecurityServiceResolver.requireSingleService(
            AuthorizationService.class,
            java.util.List.of(new FirstAuthorizationService(), new SecondAuthorizationService())));

    assertTrue(ex.getMessage().contains("multiple implementations"));
    assertTrue(ex.getMessage().contains(FirstAuthorizationService.class.getName()));
    assertTrue(ex.getMessage().contains(SecondAuthorizationService.class.getName()));
  }

  @Test
  @DisplayName("resetAll clears cached services")
  void resetAll_clearsCaches() {
    // After reset, a subsequent call should attempt SPI lookup again.
    // Since no SPI is registered in the test env, it should throw.
    SecurityServiceResolver.resetAll();
    assertThrows(IllegalStateException.class,
        SecurityServiceResolver::authenticationService);
  }

  @Test
  @DisplayName("resetAll also clears the SubjectStore cache")
  void resetAll_clearsSubjectStore() {
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    assertTrue(SubjectStores.findSubjectStore().isPresent(),
        "precondition: subject store cached");

    SecurityServiceResolver.resetAll();

    assertTrue(SubjectStores.findSubjectStore().isEmpty(),
        "resetAll() must reset SubjectStores too");
  }

  @Test
  @DisplayName("findSingleService returns the only registered service")
  void findSingleService_singleEntry() {
    FirstAuthenticationService only = new FirstAuthenticationService();

    var found = SecurityServiceResolver.findSingleService(
        AuthenticationService.class,
        java.util.List.of(only));

    assertTrue(found.isPresent());
    assertSame(only, found.get());
  }

  @Test
  @DisplayName("findSingleService returns empty for an empty service iterable")
  void findSingleService_empty() {
    var found = SecurityServiceResolver.findSingleService(
        AuthenticationService.class, java.util.List.of());

    assertTrue(found.isEmpty());
  }

  @Test
  @DisplayName("requireSingleService returns the only registered service")
  void requireSingleService_singleEntry() {
    FirstAuthenticationService only = new FirstAuthenticationService();

    AuthenticationService<?, ?> resolved = SecurityServiceResolver.requireSingleService(
        AuthenticationService.class,
        java.util.List.of(only));

    assertSame(only, resolved);
  }

  static class FirstAuthenticationService implements AuthenticationService<String, String> {
    @Override
    public boolean checkCredentials(String credentials) {
      return false;
    }

    @Override
    public String loadSubject(String credentials) {
      return credentials;
    }

    @Override
    public Class<String> subjectType() {
      return String.class;
    }
  }

  static final class SecondAuthenticationService extends FirstAuthenticationService {
  }

  static class FirstAuthorizationService implements AuthorizationService<String> {
    @Override
    public com.svenruppert.vaadin.security.authorization.api.roles.HasRoles rolesFor(String subject) {
      return java.util.List::of;
    }
  }

  static final class SecondAuthorizationService extends FirstAuthorizationService {
  }
}
