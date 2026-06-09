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
package com.svenruppert.jsentinel.test;

import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Fluent test-fixture builder that wires {@link FakeAuthenticationService},
 * {@link FakeAuthorizationService} and {@link InMemorySubjectStore} for a
 * single {@link JSentinelSubject} and binds the subject as the current
 * caller. Closing the fixture (try-with-resources) clears the subject
 * binding.
 *
 * <p>Use this in test code instead of stamping out the FakeAuthN +
 * FakeAuthZ + SubjectStore + JSentinelServiceResolver scaffolding by
 * hand.
 *
 * <pre>
 *   try (JSentinelTestFixture fixture = JSentinelTestFixture.builder()
 *       .subject("alice")
 *       .role("ROLE_ADMIN")
 *       .permission("doc:read")
 *       .build()) {
 *
 *     // act-and-assert as if alice were logged in
 *   }
 * </pre>
 *
 * <p>Or run a block with the subject bound:
 *
 * <pre>
 *   JSentinelTestFixture.runAs(adminSubject, () -> {
 *     // act-and-assert
 *   });
 * </pre>
 *
 * @since 00.74.00
 */
public final class JSentinelTestFixture implements AutoCloseable {

  private final JSentinelSubject subject;

  private JSentinelTestFixture(JSentinelSubject subject) {
    this.subject = subject;
  }

  /** @return the bound subject */
  public JSentinelSubject subject() {
    return subject;
  }

  /**
   * Clears the {@link SubjectStores} subject binding. Idempotent.
   */
  @Override
  public void close() {
    SubjectStores.findSubjectStore()
        .ifPresent(store -> store.deleteCurrentSubject(JSentinelSubject.class));
  }

  /**
   * Convenience: binds {@code subject} as the current caller for the
   * duration of {@code block}, then clears the binding.
   *
   * <p>Requires that {@link JSentinelServiceResolver} already has a
   * {@link com.svenruppert.jsentinel.authentication.AuthenticationService}
   * + {@link com.svenruppert.jsentinel.authorization.api.AuthorizationService}
   * wired for {@link JSentinelSubject}. For a self-contained setup,
   * use {@link Builder#build()} which provisions both Fake services
   * automatically.
   *
   * @param subject subject to bind; non-null
   * @param block   code to run while the subject is bound; non-null
   */
  public static void runAs(JSentinelSubject subject, Runnable block) {
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(block, "block");
    SubjectStores.subjectStore().setCurrentSubject(subject, JSentinelSubject.class);
    try {
      block.run();
    } finally {
      SubjectStores.findSubjectStore()
          .ifPresent(store -> store.deleteCurrentSubject(JSentinelSubject.class));
    }
  }

  /** @return new builder */
  public static Builder builder() {
    return new Builder();
  }

  /** Fluent builder for a fully wired test fixture. */
  public static final class Builder {
    private String subjectId;
    private String displayName;
    private final Set<RoleName> roles = new LinkedHashSet<>();
    private final Set<PermissionName> permissions = new LinkedHashSet<>();

    private Builder() {
    }

    /** Sets the subject id (used as display name unless overridden). */
    public Builder subject(String subjectId) {
      this.subjectId = Objects.requireNonNull(subjectId, "subjectId");
      return this;
    }

    /** Overrides the display name. Defaults to the subject id. */
    public Builder displayName(String displayName) {
      this.displayName = Objects.requireNonNull(displayName, "displayName");
      return this;
    }

    /** Adds a role. May be called multiple times. */
    public Builder role(String roleName) {
      this.roles.add(new RoleName(Objects.requireNonNull(roleName, "roleName")));
      return this;
    }

    /** Adds several roles in one call. */
    public Builder roles(String... roleNames) {
      Objects.requireNonNull(roleNames, "roleNames");
      for (String r : roleNames) {
        this.roles.add(new RoleName(r));
      }
      return this;
    }

    /** Adds a permission. May be called multiple times. */
    public Builder permission(String permissionName) {
      this.permissions.add(new PermissionName(
          Objects.requireNonNull(permissionName, "permissionName")));
      return this;
    }

    /** Adds several permissions in one call. */
    public Builder permissions(String... permissionNames) {
      Objects.requireNonNull(permissionNames, "permissionNames");
      for (String p : permissionNames) {
        this.permissions.add(new PermissionName(p));
      }
      return this;
    }

    /**
     * Builds the fixture, wires Fake AuthN + AuthZ services into the
     * {@link JSentinelServiceResolver}, registers an
     * {@link InMemorySubjectStore} as the active subject store, and
     * binds the constructed subject.
     */
    public JSentinelTestFixture build() {
      if (subjectId == null || subjectId.isBlank()) {
        throw new IllegalStateException("subject(...) must be set before build()");
      }
      String name = displayName != null ? displayName : subjectId;
      JSentinelSubject subject = new JSentinelSubject(subjectId, name, roles, permissions);

      FakeAuthenticationService<String, JSentinelSubject> authn =
          FakeAuthenticationService.forType(JSentinelSubject.class);
      FakeAuthorizationService<JSentinelSubject> authz = new FakeAuthorizationService<>();
      authz.putRoles(subject, roles);
      authz.putPermissions(subject, permissions);

      JSentinelServiceResolver.setAuthenticationService(authn);
      JSentinelServiceResolver.setAuthorizationService(authz);

      InMemorySubjectStore store = new InMemorySubjectStore();
      SubjectStores.setSubjectStore(store);
      store.setCurrentSubject(subject, JSentinelSubject.class);

      return new JSentinelTestFixture(subject);
    }
  }
}
