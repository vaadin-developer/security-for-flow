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
package com.svenruppert.vaadin.security.credential.password.envelope;

import com.svenruppert.vaadin.security.credential.CredentialType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordHashCodecTest {

  private static final String SECRET_INNER_HASH = "supersecrethash==";
  private static final String SECRET_PEPPER_ID = "pepper-2026-04";
  private static final String SECRET_SALT = "ZGVhZGJlZWY=";

  private final PasswordHashCodec codec = PasswordHashCodec.DEFAULT;

  private PasswordHashEnvelope sampleWithoutPepper() {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("i", "210000");
    params.put("s", SECRET_SALT);
    return new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        "PBKDF2WithHmacSHA256",
        "pbkdf2-jdk",
        1,
        Optional.empty(),
        params,
        SECRET_INNER_HASH
    );
  }

  private PasswordHashEnvelope sampleWithPepper() {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("i", "210000");
    params.put("s", SECRET_SALT);
    return new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1,
        CredentialType.PASSWORD,
        "PBKDF2WithHmacSHA256",
        "pbkdf2-jdk",
        1,
        Optional.of(SECRET_PEPPER_ID),
        params,
        SECRET_INNER_HASH
    );
  }

  @Test
  @DisplayName("encode produces a canonical wire form with the $pwh$ marker")
  void encodeProducesCanonicalWire() {
    String encoded = codec.encode(sampleWithoutPepper());
    assertTrue(encoded.startsWith("$pwh$v=1$"));
    assertTrue(encoded.contains("$ct=PASSWORD$"));
    assertTrue(encoded.contains("$alg=PBKDF2WithHmacSHA256$"));
    assertTrue(encoded.contains("$prov=pbkdf2-jdk$"));
    assertTrue(encoded.contains("$pol=1$"));
    assertFalse(encoded.contains("$pep="),
        "pepper field must be omitted when absent");
    assertTrue(encoded.contains("$p=i=210000,s=" + SECRET_SALT + "$"));
    assertTrue(encoded.endsWith("$h=" + SECRET_INNER_HASH));
  }

  @Test
  @DisplayName("encode includes pepper field when present")
  void encodeIncludesPepperWhenPresent() {
    String encoded = codec.encode(sampleWithPepper());
    assertTrue(encoded.contains("$pep=" + SECRET_PEPPER_ID + "$"));
  }

  @Test
  @DisplayName("Roundtrip: encode -> decode -> encode reproduces the same string")
  void roundtripWithoutPepper() {
    PasswordHashEnvelope original = sampleWithoutPepper();
    String first = codec.encode(original);
    PasswordHashRecord parsed = codec.decode(first);
    assertEquals(first, parsed.encoded());
    assertEquals(original, parsed.envelope());
    assertEquals(first, codec.encode(parsed.envelope()));
  }

  @Test
  @DisplayName("Roundtrip with pepper")
  void roundtripWithPepper() {
    String first = codec.encode(sampleWithPepper());
    PasswordHashRecord parsed = codec.decode(first);
    assertEquals(first, codec.encode(parsed.envelope()));
    assertEquals(Optional.of(SECRET_PEPPER_ID), parsed.envelope().pepperKeyId());
  }

  @Test
  @DisplayName("decode rejects null input")
  void decodeRejectsNull() {
    assertThrows(PasswordHashFormatException.class, () -> codec.decode(null));
  }

  @Test
  @DisplayName("decode rejects blank input")
  void decodeRejectsBlank() {
    assertThrows(PasswordHashFormatException.class, () -> codec.decode(""));
    assertThrows(PasswordHashFormatException.class, () -> codec.decode("   "));
  }

  @Test
  @DisplayName("decode rejects missing $pwh$ marker")
  void decodeRejectsMissingMarker() {
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$p=$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$p=$h=x"));
  }

  @Test
  @DisplayName("decode rejects unknown newer format version")
  void decodeRejectsUnknownFormatVersion() {
    String unknown = "$pwh$v=999$ct=PASSWORD$alg=A$prov=p$pol=1$p=$h=x";
    PasswordHashFormatException ex = assertThrows(
        PasswordHashFormatException.class, () -> codec.decode(unknown));
    assertTrue(ex.getMessage().toLowerCase().contains("format version"));
  }

  @Test
  @DisplayName("decode rejects negative format version wire value")
  void decodeRejectsNegativeFormatVersion() {
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=-1$ct=PASSWORD$alg=A$prov=p$pol=1$p=$h=x"));
  }

  @Test
  @DisplayName("decode rejects non-integer format version")
  void decodeRejectsNonIntegerFormatVersion() {
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=abc$ct=PASSWORD$alg=A$prov=p$pol=1$p=$h=x"));
  }

  @Test
  @DisplayName("decode rejects each missing mandatory field")
  void decodeRejectsMissingFields() {
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$ct=PASSWORD$alg=A$prov=p$pol=1$p=$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$alg=A$prov=p$pol=1$p=$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$prov=p$pol=1$p=$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$pol=1$p=$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$prov=p$p=$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$p="));
  }

  @Test
  @DisplayName("decode rejects duplicate fields")
  void decodeRejectsDuplicateFields() {
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$p=$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$p=$h=x$h=y"));
  }

  @Test
  @DisplayName("decode rejects unknown field names")
  void decodeRejectsUnknownFields() {
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$p=$h=x$zzz=foo"));
  }

  @Test
  @DisplayName("decode rejects unknown credential type")
  void decodeRejectsUnknownCredentialType() {
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=WEBAUTHN$alg=A$prov=p$pol=1$p=$h=x"));
  }

  @Test
  @DisplayName("decode rejects malformed parameter entries")
  void decodeRejectsMalformedParams() {
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$p=noEquals$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$p=,$h=x"));
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$p==value$h=x"));
  }

  @Test
  @DisplayName("decode rejects empty pepper key id")
  void decodeRejectsBlankPepper() {
    assertThrows(PasswordHashFormatException.class,
        () -> codec.decode("$pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$pep=$p=$h=x"));
  }

  @Test
  @DisplayName("encode rejects values that contain separator characters")
  void encodeRejectsForbiddenSeparators() {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("i", "210000");

    PasswordHashEnvelope withDollar = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1, CredentialType.PASSWORD,
        "Bad$Alg", "pbkdf2-jdk", 1, Optional.empty(), params, "h");
    assertThrows(PasswordHashFormatException.class,
        () -> codec.encode(withDollar));

    PasswordHashEnvelope withComma = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1, CredentialType.PASSWORD,
        "Alg", "pbkdf2-jdk,evil", 1, Optional.empty(), params, "h");
    assertThrows(PasswordHashFormatException.class,
        () -> codec.encode(withComma));

    Map<String, String> badParams = new LinkedHashMap<>();
    badParams.put("i", "210000$injected");
    PasswordHashEnvelope withInjectedParam = new PasswordHashEnvelope(
        PasswordHashFormatVersion.V1, CredentialType.PASSWORD,
        "Alg", "pbkdf2-jdk", 1, Optional.empty(), badParams, "h");
    assertThrows(PasswordHashFormatException.class,
        () -> codec.encode(withInjectedParam));
  }

  @Test
  @DisplayName("Codec emits CredentialType.PASSWORD as the default Phase-1a discriminator")
  void credentialTypeDefaultsToPassword() {
    PasswordHashRecord parsed = codec.decode(codec.encode(sampleWithoutPepper()));
    assertEquals(CredentialType.PASSWORD, parsed.envelope().credentialType());
  }

  @Test
  @DisplayName("Exception messages never embed inner hash, salt or pepper id")
  void exceptionMessagesDoNotLeakSecrets() {
    String input =
        "$pwh$v=1$ct=PASSWORD$alg=A$prov=p$pol=1$pep="
        + SECRET_PEPPER_ID
        + "$p=s=" + SECRET_SALT
        + "$h=" + SECRET_INNER_HASH
        + "$zzz=foo";
    PasswordHashFormatException ex = assertThrows(
        PasswordHashFormatException.class, () -> codec.decode(input));
    String message = ex.getMessage() == null ? "" : ex.getMessage();
    assertFalse(message.contains(SECRET_INNER_HASH),
        "exception leaked inner hash");
    assertFalse(message.contains(SECRET_PEPPER_ID),
        "exception leaked pepper key id");
    assertFalse(message.contains(SECRET_SALT),
        "exception leaked salt");
  }

  @Test
  @DisplayName("PasswordHashEnvelope.toString never exposes inner hash, salt or pepper id")
  void envelopeToStringRedacts() {
    String text = sampleWithPepper().toString();
    assertFalse(text.contains(SECRET_INNER_HASH));
    assertFalse(text.contains(SECRET_PEPPER_ID));
    assertFalse(text.contains(SECRET_SALT));
    assertTrue(text.contains("<redacted>"));
    assertTrue(text.contains("<present>"));
  }

  @Test
  @DisplayName("PasswordHashRecord.toString never exposes the encoded envelope")
  void recordToStringRedacts() {
    PasswordHashRecord r = codec.decode(codec.encode(sampleWithoutPepper()));
    String text = r.toString();
    assertFalse(text.contains(SECRET_INNER_HASH));
    assertFalse(text.contains(SECRET_SALT));
    assertTrue(text.contains("<redacted>"));
  }

  @Test
  @DisplayName("PasswordHashFormatVersion.fromWireValue rejects unknown values")
  void formatVersionFromWireRejectsUnknown() {
    assertSame(PasswordHashFormatVersion.V1,
        PasswordHashFormatVersion.fromWireValue(1));
    assertThrows(PasswordHashFormatException.class,
        () -> PasswordHashFormatVersion.fromWireValue(2));
    assertThrows(PasswordHashFormatException.class,
        () -> PasswordHashFormatVersion.fromWireValue(0));
  }

  @Test
  @DisplayName("CURRENT format version is the highest known")
  void currentMatchesMaxKnownWire() {
    assertEquals(PasswordHashFormatVersion.CURRENT.wireValue(),
        PasswordHashFormatVersion.MAX_KNOWN_WIRE_VALUE);
  }
}
