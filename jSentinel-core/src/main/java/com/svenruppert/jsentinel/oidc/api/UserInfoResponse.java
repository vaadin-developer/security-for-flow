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
package com.svenruppert.jsentinel.oidc.api;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The claims returned by the OIDC UserInfo endpoint (OIDC Core §5.3, V00.78). The
 * {@code sub} claim is mandatory and MUST match the ID token's {@code sub} (the RP
 * verifies this) — the rest are provider-specific profile claims.
 *
 * @param subject the {@code sub} claim (mandatory)
 * @param claims  the full claim set (immutable; includes {@code sub})
 * @since 00.78.00
 */
public record UserInfoResponse(String subject, Map<String, Object> claims) {

  public UserInfoResponse {
    Objects.requireNonNull(subject, "subject");
    claims = Map.copyOf(Objects.requireNonNull(claims, "claims"));
  }

  /** @return the claim {@code name} as {@code type}, if present and assignable. */
  public <T> Optional<T> claim(String name, Class<T> type) {
    Object value = claims.get(name);
    return type.isInstance(value) ? Optional.of(type.cast(value)) : Optional.empty();
  }
}
