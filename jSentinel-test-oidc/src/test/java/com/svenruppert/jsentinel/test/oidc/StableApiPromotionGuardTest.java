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
package com.svenruppert.jsentinel.test.oidc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * V00.79 stable-API promotion guard. The V00.76 JWT, V00.77 OAuth2 and V00.78 OIDC
 * surfaces are promoted to stable — this test locks that in by asserting a
 * representative sample no longer carries {@link ExperimentalJSentinelApi}, so a
 * future change cannot silently re-mark them experimental (a SemVer regression).
 * The V00.79-new types (e.g. {@code VendorProfile}) are still soaking and MUST keep
 * the marker.
 */
@DisplayName("V00.79 stable-API promotion guard")
class StableApiPromotionGuardTest {

  private static final Class<?>[] PROMOTED = {
      // V00.76 JWT
      com.svenruppert.jsentinel.jwt.api.JwtValidator.class,
      com.svenruppert.jsentinel.jwt.api.ValidatedJwt.class,
      com.svenruppert.jsentinel.jwt.api.JwtValidationError.class,
      com.svenruppert.jsentinel.jwt.api.JwksClient.class,
      com.svenruppert.jsentinel.jwt.api.JwtSigner.class,
      com.svenruppert.jsentinel.dx.bootstrap.JwtBootstrap.class,
      // V00.77 OAuth2
      com.svenruppert.jsentinel.oauth2.api.AuthorizationCodeFlow.class,
      com.svenruppert.jsentinel.oauth2.api.TokenEndpointClient.class,
      com.svenruppert.jsentinel.oauth2.api.TokenResponse.class,
      com.svenruppert.jsentinel.oauth2.api.OAuth2Error.class,
      com.svenruppert.jsentinel.oauth2.api.ClientAuthentication.class,
      com.svenruppert.jsentinel.oauth2.api.StateStore.class,
      com.svenruppert.jsentinel.dx.bootstrap.OAuth2Bootstrap.class,
      // V00.78 OIDC
      com.svenruppert.jsentinel.oidc.api.IdTokenValidator.class,
      com.svenruppert.jsentinel.oidc.api.ValidatedIdToken.class,
      com.svenruppert.jsentinel.oidc.api.OidcDiscoveryClient.class,
      com.svenruppert.jsentinel.oidc.api.UserInfoClient.class,
      com.svenruppert.jsentinel.oidc.api.ClaimsToSubjectMapper.class,
      com.svenruppert.jsentinel.oidc.api.ClaimsToRolesMapper.class,
      com.svenruppert.jsentinel.oidc.api.LogoutInitiator.class,
      com.svenruppert.jsentinel.dx.bootstrap.OidcBootstrap.class,
  };

  private static final Class<?>[] STILL_EXPERIMENTAL = {
      // V00.79-new — own soak time
      com.svenruppert.jsentinel.oidc.api.VendorProfile.class,
  };

  @Test
  @DisplayName("the promoted V00.76/77/78 surface no longer carries @ExperimentalJSentinelApi")
  void promotedTypesAreStable() {
    for (Class<?> type : PROMOTED) {
      assertFalse(type.isAnnotationPresent(ExperimentalJSentinelApi.class),
          type.getName() + " must be promoted to stable (no @ExperimentalJSentinelApi)");
    }
  }

  @Test
  @DisplayName("V00.79-new types still carry @ExperimentalJSentinelApi")
  void newTypesStayExperimental() {
    for (Class<?> type : STILL_EXPERIMENTAL) {
      assertTrue(type.isAnnotationPresent(ExperimentalJSentinelApi.class),
          type.getName() + " is V00.79-new and must keep @ExperimentalJSentinelApi");
    }
  }

  @Test
  @DisplayName("R-EXIT: a stable type that exposes an experimental type does so via an experimental method")
  void experimentalLeakIsMarkedAtTheMethod() throws NoSuchMethodException {
    // OidcBootstrap is stable but .vendor(VendorProfile) takes a kept-experimental
    // type — the method itself must stay experimental so the soak status propagates.
    var vendor = com.svenruppert.jsentinel.dx.bootstrap.OidcBootstrap.class
        .getMethod("vendor", com.svenruppert.jsentinel.oidc.api.VendorProfile.class);
    assertTrue(vendor.isAnnotationPresent(ExperimentalJSentinelApi.class),
        "OidcBootstrap.vendor(VendorProfile) must be @ExperimentalJSentinelApi (it exposes an "
            + "experimental type from an otherwise-stable interface)");
  }
}
