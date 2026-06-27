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
package com.svenruppert.jsentinel.identity.vendor.google;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.jwt.api.JoseHeader;
import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;
import com.svenruppert.jsentinel.oidc.api.ValidatedIdToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("GoogleProfile — tenant from the hosted-domain hd claim")
class GoogleProfileTest {

  private static ValidatedIdToken idToken(Map<String, Object> claims) {
    return new ValidatedIdToken(new ValidatedJwt("c",
        new JoseHeader("RS256", Optional.empty(), Optional.empty()), claims, Instant.now()),
        Optional.empty(), Optional.empty(), Optional.empty(), List.of(), Optional.empty(),
        Optional.empty());
  }

  @Test
  @DisplayName("maps hd to the tenant; absent hd yields no tenant")
  void mapsHostedDomain() {
    assertEquals(Optional.of(TenantId.of("example.com")),
        GoogleProfile.INSTANCE.tenantMapper().orElseThrow()
            .mapTenant(idToken(Map.of("hd", "example.com")), Optional.empty()));
    assertTrue(GoogleProfile.INSTANCE.tenantMapper().orElseThrow()
        .mapTenant(idToken(Map.of("sub", "x")), Optional.empty()).isEmpty());
    assertEquals("google", GoogleProfile.INSTANCE.id());
  }
}
