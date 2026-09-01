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
package eu.jsentinel.jcustos.test.oidc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Stable-API promotion guard. The V00.76 JWT, V00.77 OAuth2, V00.78 OIDC and
 * V00.74 token-propagation surfaces are promoted to stable — this test locks that
 * in by asserting a representative sample no longer carries
 * {@link ExperimentalJCustosApi}, so a future change cannot silently re-mark them
 * experimental (a SemVer regression). Types still inside their soak window (e.g.
 * {@code VendorProfile}) MUST keep the marker.
 */
@DisplayName("stable-API promotion guard (V00.76–V00.83)")
class StableApiPromotionGuardTest {

  private static final Class<?>[] PROMOTED = {
      // V00.76 JWT
      eu.jsentinel.jcustos.jwt.api.JwtValidator.class,
      eu.jsentinel.jcustos.jwt.api.ValidatedJwt.class,
      eu.jsentinel.jcustos.jwt.api.JwtValidationError.class,
      eu.jsentinel.jcustos.jwt.api.JwksClient.class,
      eu.jsentinel.jcustos.jwt.api.JwtSigner.class,
      eu.jsentinel.jcustos.dx.bootstrap.JwtBootstrap.class,
      // V00.77 OAuth2
      eu.jsentinel.jcustos.oauth2.api.AuthorizationCodeFlow.class,
      eu.jsentinel.jcustos.oauth2.api.TokenEndpointClient.class,
      eu.jsentinel.jcustos.oauth2.api.TokenResponse.class,
      eu.jsentinel.jcustos.oauth2.api.OAuth2Error.class,
      eu.jsentinel.jcustos.oauth2.api.ClientAuthentication.class,
      eu.jsentinel.jcustos.oauth2.api.StateStore.class,
      eu.jsentinel.jcustos.dx.bootstrap.OAuth2Bootstrap.class,
      // V00.78 OIDC
      eu.jsentinel.jcustos.oidc.api.IdTokenValidator.class,
      eu.jsentinel.jcustos.oidc.api.ValidatedIdToken.class,
      eu.jsentinel.jcustos.oidc.api.OidcDiscoveryClient.class,
      eu.jsentinel.jcustos.oidc.api.UserInfoClient.class,
      eu.jsentinel.jcustos.oidc.api.ClaimsToSubjectMapper.class,
      eu.jsentinel.jcustos.oidc.api.ClaimsToRolesMapper.class,
      eu.jsentinel.jcustos.oidc.api.LogoutInitiator.class,
      eu.jsentinel.jcustos.dx.bootstrap.OidcBootstrap.class,
      // V00.74 token propagation — promoted in V00.83 once the demo
      // adoption its Javadoc made a condition actually landed
      eu.jsentinel.jcustos.annotations.PropagateToken.class,
      eu.jsentinel.jcustos.credential.propagation.TokenCredential.class,
      eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore.class,
      eu.jsentinel.jcustos.credential.propagation.OutboundTokenStrategy.class,
      eu.jsentinel.jcustos.credential.propagation.OutboundHeaderContext.class,
      eu.jsentinel.jcustos.credential.propagation.OutboundCall.class,
      eu.jsentinel.jcustos.credential.propagation.HeaderValue.class,
      eu.jsentinel.jcustos.credential.propagation.BearerToken.class,
      eu.jsentinel.jcustos.credential.propagation.PassThroughStrategy.class,
      eu.jsentinel.jcustos.credential.propagation.PropagateTokenAdvisor.class,
      eu.jsentinel.jcustos.propagation.proxy.PropagatingProxy.class,
      eu.jsentinel.jcustos.propagation.oidc.strategy.TokenExchangeStrategy.class,
      eu.jsentinel.jcustos.propagation.oidc.cache.TokenExchangeCache.class,
      eu.jsentinel.jcustos.dx.bootstrap.PropagationBootstrap.class,
      // V00.76/00.77 identity implementations — promoted in V00.83
      eu.jsentinel.jcustos.jwt.impl.HttpJwksClient.class,
      eu.jsentinel.jcustos.jwt.impl.NimbusJwtValidator.class,
      eu.jsentinel.jcustos.jwt.impl.NimbusJwtSigner.class,
      eu.jsentinel.jcustos.oauth2.HttpAuthorizationCodeFlow.class,
      eu.jsentinel.jcustos.oauth2.HttpTokenEndpointClient.class,
      eu.jsentinel.jcustos.oauth2.RefreshTokenRotator.class,
      // V00.74 DX surface — promoted in V00.83
      eu.jsentinel.jcustos.dx.runtime.Health.class,
      eu.jsentinel.jcustos.dx.runtime.HealthStatus.class,
  };

  private static final Class<?>[] STILL_EXPERIMENTAL = {
      // Deliberately kept — see the keep table in RELEASE-NOTES-00.83.00.md
      eu.jsentinel.jcustos.oidc.api.VendorProfile.class,
      // V00.79.20 hardening group: awaiting its own audit, not its soak time
      eu.jsentinel.jcustos.oauth2.MutualTls.class,
      eu.jsentinel.jcustos.oauth2.AuthorizationRequestSigner.class,
      // Permission API: the marker is a design statement ("use role-based
      // access for stable production use"), not a soak status
      eu.jsentinel.jcustos.authorization.api.permissions.PermissionName.class,
  };

  @Test
  @DisplayName("the promoted V00.76/77/78 surface no longer carries @ExperimentalJCustosApi")
  void promotedTypesAreStable() {
    for (Class<?> type : PROMOTED) {
      assertFalse(type.isAnnotationPresent(ExperimentalJCustosApi.class),
          type.getName() + " must be promoted to stable (no @ExperimentalJCustosApi)");
    }
  }

  @Test
  @DisplayName("V00.79-new types still carry @ExperimentalJCustosApi")
  void newTypesStayExperimental() {
    for (Class<?> type : STILL_EXPERIMENTAL) {
      assertTrue(type.isAnnotationPresent(ExperimentalJCustosApi.class),
          type.getName() + " is V00.79-new and must keep @ExperimentalJCustosApi");
    }
  }

  @Test
  @DisplayName("the propagation accessors on JCustosServiceResolver are promoted too")
  void propagationResolverAccessorsAreStable() throws NoSuchMethodException {
    // The resolver class is stable and marks individual methods instead. The
    // five propagation accessors were promoted in V00.83 alongside the types
    // they hand out — leaving them marked would have kept the surface
    // experimental through the back door.
    Class<?> resolver = eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver.class;
    var accessors = new java.lang.reflect.Method[] {
        resolver.getMethod("tokenCredentialStore"),
        resolver.getMethod("findTokenCredentialStore"),
        resolver.getMethod("setTokenCredentialStore",
            eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore.class),
        resolver.getMethod("registerOutboundTokenStrategy", String.class,
            eu.jsentinel.jcustos.credential.propagation.OutboundTokenStrategy.class),
        resolver.getMethod("findOutboundTokenStrategy", String.class),
    };
    for (var accessor : accessors) {
      assertFalse(accessor.isAnnotationPresent(ExperimentalJCustosApi.class),
          "JCustosServiceResolver." + accessor.getName()
              + " hands out a promoted propagation type and must be stable too");
    }
  }

  @Test
  @DisplayName("the V00.74.10 tooling methods on JCustosRuntime are promoted")
  void runtimeToolingMethodsAreStable() throws NoSuchMethodException {
    Class<?> runtime = eu.jsentinel.jcustos.dx.runtime.JCustosRuntime.class;
    for (String name : new String[] {"summary", "toMap", "toJson", "healthCheck"}) {
      assertFalse(runtime.getMethod(name).isAnnotationPresent(ExperimentalJCustosApi.class),
          "JCustosRuntime." + name + "() is V00.74.10 tooling API and must be stable");
    }
  }

  @Test
  @DisplayName("R-EXIT: a stable type that exposes an experimental type does so via an experimental method")
  void experimentalLeakIsMarkedAtTheMethod() throws NoSuchMethodException {
    // OidcBootstrap is stable but .vendor(VendorProfile) takes a kept-experimental
    // type — the method itself must stay experimental so the soak status propagates.
    var vendor = eu.jsentinel.jcustos.dx.bootstrap.OidcBootstrap.class
        .getMethod("vendor", eu.jsentinel.jcustos.oidc.api.VendorProfile.class);
    assertTrue(vendor.isAnnotationPresent(ExperimentalJCustosApi.class),
        "OidcBootstrap.vendor(VendorProfile) must be @ExperimentalJCustosApi (it exposes an "
            + "experimental type from an otherwise-stable interface)");
  }
}
