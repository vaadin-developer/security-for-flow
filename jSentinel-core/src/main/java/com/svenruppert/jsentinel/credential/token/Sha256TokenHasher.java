/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.jsentinel.credential.token;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Shipped default {@link TokenHasher}: SHA-256 over the token's UTF-8 bytes,
 * rendered as lowercase hex. Deterministic and lookup-safe for high-entropy
 * tokens — never for human-chosen passwords (use the password-hashing pipeline
 * for those).
 *
 * @since 00.75.10
 */
@ExperimentalJSentinelApi
public final class Sha256TokenHasher implements TokenHasher {

  @Override
  public String hash(char[] token) {
    if (token == null) {
      throw new IllegalArgumentException("token must not be null");
    }
    byte[] input = new String(token).getBytes(StandardCharsets.UTF_8);
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(digest.digest(input));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 must be available", e);
    }
  }
}
