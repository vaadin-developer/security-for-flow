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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.demo.rest.domain.DemoUser;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory demo token store. Demo-only — not a production token mechanism.
 * <p>
 * Production systems must use cryptographically signed tokens with expiry,
 * refresh, and revocation policies.
 */
public final class DemoTokenStore {

  private final ConcurrentMap<String, DemoUser> tokens = new ConcurrentHashMap<>();
  private final SecureRandom random = new SecureRandom();

  public String issue(DemoUser user) {
    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    String token = HexFormat.of().formatHex(bytes);
    tokens.put(token, user);
    return token;
  }

  public Optional<DemoUser> resolve(String token) {
    if (token == null || token.isBlank()) return Optional.empty();
    return Optional.ofNullable(tokens.get(token));
  }

  public void revoke(String token) {
    if (token != null) tokens.remove(token);
  }
}
