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
package com.svenruppert.jsentinel.demo.skill.vaadin.security.oidc;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.svenruppert.jsentinel.demo.skill.vaadin.security.oidc.VendorProfileOidcExample.Idp;
import com.svenruppert.jsentinel.dx.vaadin.bootstrap.VaadinJSentinelBootstrap;

import java.net.URI;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Exercises the vendor-profile OIDC wiring for each IdP against a real
 * {@code VaadinSecurity.bootstrap()} — the recording succeeds (the vendor profile is
 * accepted), without installing (no live IdP required). Proves the public vendor-profile
 * API composes end-to-end from the consumer side.
 */
@DisplayName("Vendor-profile OIDC example records each IdP's wiring")
class VendorProfileOidcExampleTest {

  @ParameterizedTest
  @EnumSource(Idp.class)
  @DisplayName("each vendor profile records a complete OIDC bootstrap")
  void eachVendorConfigures(Idp idp) {
    VaadinJSentinelBootstrap bootstrap = VendorProfileOidcExample.configure(
        idp, "https://idp.example.com/", "rp-client", "s3cret",
        URI.create("https://app.example.com/oauth2/callback"));
    assertNotNull(bootstrap, "vendor " + idp + " records a bootstrap");
  }
}
