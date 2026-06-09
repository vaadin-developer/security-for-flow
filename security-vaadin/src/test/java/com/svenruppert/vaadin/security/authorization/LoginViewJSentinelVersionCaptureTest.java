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
package com.svenruppert.vaadin.security.authorization;

import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectIdResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import com.svenruppert.vaadin.security.session.InMemoryJSentinelVersionStore;
import com.svenruppert.vaadin.security.session.JSentinelVersion;
import com.svenruppert.vaadin.security.session.JSentinelVersionKey;
import com.svenruppert.vaadin.security.session.vaadin.VaadinJSentinelVersionContext;
import com.svenruppert.vaadin.security.test.InMemorySubjectStore;
import com.vaadin.flow.component.textfield.PasswordField;
import com.vaadin.flow.component.textfield.TextField;
import com.vaadin.flow.internal.CurrentInstance;
import com.vaadin.flow.server.VaadinSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Phase 4c-Followup: verifies that {@link LoginView#validate()}
 * auto-captures the {@link JSentinelVersion} snapshot into
 * {@link VaadinJSentinelVersionContext} whenever both
 * {@code JSentinelVersionStore} and {@code SubjectIdResolver} are
 * wired, and that the capture is a graceful no-op otherwise.
 */
@DisplayName("LoginView — auto JSentinelVersion snapshot capture")
class LoginViewJSentinelVersionCaptureTest {

  private static final String ALICE = "alice";

  @BeforeEach
  void setUp() {
    CurrentInstance.clearAll();
    JSentinelServiceResolver.resetAll();
    SubjectStores.reset();
  }

  @AfterEach
  void tearDown() {
    CurrentInstance.clearAll();
    JSentinelServiceResolver.resetAll();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("both SPIs wired → validate() captures the current JSentinelVersion onto the session")
  void captureWhenSpisWired() throws Exception {
    InMemoryVaadinSession session = bindSession();
    InMemorySubjectStore subjectStore = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(subjectStore);
    subjectStore.setCurrentSubject(ALICE, String.class);

    InMemoryJSentinelVersionStore versionStore = new InMemoryJSentinelVersionStore();
    JSentinelVersionKey aliceKey = new JSentinelVersionKey(TenantId.DEFAULT, new SubjectId(ALICE));
    versionStore.increment(aliceKey); // current → 1
    versionStore.increment(aliceKey); // current → 2

    JSentinelServiceResolver.setJSentinelVersionStore(versionStore);
    JSentinelServiceResolver.setSubjectIdResolver(stringSubjectIdResolver());

    TestLoginView view = new TestLoginView();
    view.acceptCredentials = true;
    setField(view, "username", TextField.class, "u");
    setField(view, "password", PasswordField.class, "p");

    invokeValidate(view);
    VaadinSession.setCurrent(session);   // restore — validate() may wipe CurrentInstance

    Optional<VaadinJSentinelVersionContext.Snapshot> snapOpt =
        VaadinJSentinelVersionContext.current(session);
    assertTrue(snapOpt.isPresent(),
        "snapshot must be recorded when both SPIs are configured");
    assertEquals(new SubjectId(ALICE), snapOpt.get().subjectId());
    assertEquals(TenantId.DEFAULT, snapOpt.get().tenant());
    assertEquals(new JSentinelVersion(2L), snapOpt.get().snapshot(),
        "captured snapshot must equal the store's current value at login time");
  }

  @Test
  @DisplayName("no JSentinelVersionStore → capture is skipped, session attribute stays unset")
  void noStoreSkipsCapture() throws Exception {
    InMemoryVaadinSession session = bindSession();
    InMemorySubjectStore subjectStore = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(subjectStore);
    subjectStore.setCurrentSubject(ALICE, String.class);
    JSentinelServiceResolver.setSubjectIdResolver(stringSubjectIdResolver());
    // intentionally: no setJSentinelVersionStore()

    TestLoginView view = new TestLoginView();
    view.acceptCredentials = true;

    invokeValidate(view);
    VaadinSession.setCurrent(session);

    assertTrue(VaadinJSentinelVersionContext.current(session).isEmpty());
  }

  @Test
  @DisplayName("no SubjectIdResolver → capture is skipped (framework cannot derive SubjectId)")
  void noResolverSkipsCapture() throws Exception {
    InMemoryVaadinSession session = bindSession();
    InMemorySubjectStore subjectStore = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(subjectStore);
    subjectStore.setCurrentSubject(ALICE, String.class);
    JSentinelServiceResolver.setJSentinelVersionStore(new InMemoryJSentinelVersionStore());
    // intentionally: no setSubjectIdResolver()

    TestLoginView view = new TestLoginView();
    view.acceptCredentials = true;

    invokeValidate(view);
    VaadinSession.setCurrent(session);

    assertTrue(VaadinJSentinelVersionContext.current(session).isEmpty());
  }

  @Test
  @DisplayName("no current subject → capture is skipped even with both SPIs wired")
  void noSubjectSkipsCapture() throws Exception {
    InMemoryVaadinSession session = bindSession();
    SubjectStores.setSubjectStore(new InMemorySubjectStore()); // empty
    JSentinelServiceResolver.setJSentinelVersionStore(new InMemoryJSentinelVersionStore());
    JSentinelServiceResolver.setSubjectIdResolver(stringSubjectIdResolver());

    TestLoginView view = new TestLoginView();
    view.acceptCredentials = true;

    invokeValidate(view);
    VaadinSession.setCurrent(session);

    assertTrue(VaadinJSentinelVersionContext.current(session).isEmpty());
  }

  @Test
  @DisplayName("resolver exceptions are swallowed — login flow is not blocked")
  void resolverExceptionSwallowed() throws Exception {
    InMemoryVaadinSession session = bindSession();
    InMemorySubjectStore subjectStore = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(subjectStore);
    subjectStore.setCurrentSubject(ALICE, String.class);

    JSentinelServiceResolver.setJSentinelVersionStore(new InMemoryJSentinelVersionStore());
    JSentinelServiceResolver.setSubjectIdResolver(new SubjectIdResolver<String>() {
      @Override public SubjectId resolve(String s) { throw new RuntimeException("boom"); }
    });

    TestLoginView view = new TestLoginView();
    view.acceptCredentials = true;

    invokeValidate(view);
    VaadinSession.setCurrent(session);

    // capture skipped, but validate() must have reached navigateToApp
    assertTrue(view.navigatedToApp,
        "login flow must complete even when snapshot capture throws");
    assertTrue(VaadinJSentinelVersionContext.current(session).isEmpty());
  }

  @Test
  @DisplayName("custom resolver (tenantFor != DEFAULT) is honored on the recorded snapshot")
  void customTenantOnSnapshot() throws Exception {
    InMemoryVaadinSession session = bindSession();
    InMemorySubjectStore subjectStore = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(subjectStore);
    subjectStore.setCurrentSubject(ALICE, String.class);

    InMemoryJSentinelVersionStore versionStore = new InMemoryJSentinelVersionStore();
    TenantId acme = new TenantId("acme");
    versionStore.increment(new JSentinelVersionKey(acme, new SubjectId(ALICE))); // acme/alice → 1
    JSentinelServiceResolver.setJSentinelVersionStore(versionStore);
    JSentinelServiceResolver.setSubjectIdResolver(new SubjectIdResolver<String>() {
      @Override public SubjectId resolve(String s) { return new SubjectId(s); }
      @Override public TenantId tenantFor(String s) { return acme; }
    });

    TestLoginView view = new TestLoginView();
    view.acceptCredentials = true;

    invokeValidate(view);
    VaadinSession.setCurrent(session);

    VaadinJSentinelVersionContext.Snapshot snap =
        VaadinJSentinelVersionContext.current(session).orElseThrow();
    assertEquals(acme, snap.tenant());
    assertEquals(new JSentinelVersion(1L), snap.snapshot());
  }

  // ── Reflection helpers (mirror LoginViewTest) ─────────────────

  private static <T> void setField(LoginView view, String name, Class<T> type, String value) throws Exception {
    Field f = LoginView.class.getDeclaredField(name);
    f.setAccessible(true);
    if (type == TextField.class) {
      ((TextField) f.get(view)).setValue(value);
    } else if (type == PasswordField.class) {
      ((PasswordField) f.get(view)).setValue(value);
    } else {
      throw new IllegalArgumentException("unsupported field type: " + type);
    }
  }

  private static void invokeValidate(LoginView view) throws Exception {
    Method m = LoginView.class.getDeclaredMethod("validate");
    m.setAccessible(true);
    m.invoke(view);
  }

  private static SubjectIdResolver<String> stringSubjectIdResolver() {
    return s -> new SubjectId(s);
  }

  private static InMemoryVaadinSession bindSession() {
    InMemoryVaadinSession session = new InMemoryVaadinSession();
    VaadinSession.setCurrent(session);
    return session;
  }

  /** Vaadin session stub mirroring the other tests. */
  static final class InMemoryVaadinSession extends VaadinSession {
    private final Map<Object, Object> attributes = new HashMap<>();
    InMemoryVaadinSession() { super(null); }
    @Override public void setAttribute(String name, Object value) {
      if (value == null) attributes.remove(name); else attributes.put(name, value);
    }
    @Override public <T> void setAttribute(Class<T> type, T value) {
      if (value == null) attributes.remove(type); else attributes.put(type, value);
    }
    @Override public Object getAttribute(String name) { return attributes.get(name); }
    @Override public <T> T getAttribute(Class<T> type) { return type.cast(attributes.get(type)); }
  }

  static final class TestLoginView extends LoginView {
    boolean acceptCredentials;
    boolean navigatedToApp;
    @Override public boolean checkCredentials() { return acceptCredentials; }
    @Override public void navigateToApp() { navigatedToApp = true; }
    @Override public void reactOnFailedLogin() { /* unused */ }
  }
}
