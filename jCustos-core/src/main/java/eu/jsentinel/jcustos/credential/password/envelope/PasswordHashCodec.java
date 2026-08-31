/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.password.envelope;

import eu.jsentinel.jcustos.credential.CredentialType;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Self-describing envelope codec for Phase-1a password-hash strings.
 *
 * <p>The wire format is a stable, human-readable string built from
 * {@code $}-separated fields:</p>
 *
 * <pre>{@code
 * $pwh$v=1$ct=PASSWORD$alg=PBKDF2WithHmacSHA256$prov=pbkdf2-jdk
 *   $pol=1[$pep=<keyId>]$p=k=v(,k=v)*$h=<innerHash>
 * }</pre>
 *
 * <p>The codec performs <em>no</em> cryptographic work. It does not run
 * key-derivation functions, validate algorithm strength or look up
 * providers. It only parses, validates the envelope structure, and
 * serialises a {@link PasswordHashEnvelope} back to a string.</p>
 *
 * <p>Exception messages emitted from this codec are deliberately
 * structural and must not embed user-supplied substrings, salts, inner
 * hashes or pepper key identifiers.</p>
 */
public final class PasswordHashCodec {

  /**
   * Shared default instance. The codec is stateless.
   */
  public static final PasswordHashCodec DEFAULT = new PasswordHashCodec();

  private static final String MARKER = "pwh";
  private static final String PREFIX = "$" + MARKER;
  private static final char FIELD_SEPARATOR = '$';
  private static final char PARAM_SEPARATOR = ',';

  private static final String FIELD_VERSION = "v";
  private static final String FIELD_CREDENTIAL_TYPE = "ct";
  private static final String FIELD_ALGORITHM = "alg";
  private static final String FIELD_PROVIDER = "prov";
  private static final String FIELD_POLICY_VERSION = "pol";
  private static final String FIELD_PEPPER_KEY_ID = "pep";
  private static final String FIELD_PARAMETERS = "p";
  private static final String FIELD_INNER_HASH = "h";

  public PasswordHashCodec() {
    // intentionally public; constructor stays trivially testable.
  }

  /**
   * Serialises the given envelope into its canonical wire form.
   *
   * @throws PasswordHashFormatException if any field carries a separator
   *                                     character that would corrupt the
   *                                     wire format
   */
  public String encode(PasswordHashEnvelope envelope) {
    Objects.requireNonNull(envelope, "envelope");

    rejectSeparators(envelope.algorithm(), "algorithm");
    rejectSeparators(envelope.providerId(), "provider");
    envelope.pepperKeyId().ifPresent(p -> rejectSeparators(p, "pepperKeyId"));
    rejectInnerHashSeparators(envelope.innerHash());
    for (Map.Entry<String, String> e : envelope.parameters().entrySet()) {
      rejectParameterKey(e.getKey());
      rejectParameterValue(e.getValue());
    }

    StringBuilder sb = new StringBuilder(PREFIX.length() + 64);
    sb.append(PREFIX);
    appendField(sb, FIELD_VERSION,
        Integer.toString(envelope.formatVersion().wireValue()));
    appendField(sb, FIELD_CREDENTIAL_TYPE, envelope.credentialType().name());
    appendField(sb, FIELD_ALGORITHM, envelope.algorithm());
    appendField(sb, FIELD_PROVIDER, envelope.providerId());
    appendField(sb, FIELD_POLICY_VERSION,
        Integer.toString(envelope.policyVersion()));
    envelope.pepperKeyId()
        .ifPresent(p -> appendField(sb, FIELD_PEPPER_KEY_ID, p));
    appendField(sb, FIELD_PARAMETERS, joinParameters(envelope.parameters()));
    appendField(sb, FIELD_INNER_HASH, envelope.innerHash());
    return sb.toString();
  }

  /**
   * Parses the given wire-form string into a {@link PasswordHashRecord}.
   *
   * @throws PasswordHashFormatException on every structural error,
   *                                     including unknown newer format
   *                                     versions, duplicate fields,
   *                                     unknown fields, missing required
   *                                     fields and forbidden characters
   */
  public PasswordHashRecord decode(String encoded) {
    if (encoded == null) {
      throw new PasswordHashFormatException("encoded must not be null");
    }
    if (encoded.isBlank()) {
      throw new PasswordHashFormatException("encoded must not be blank");
    }
    if (!encoded.startsWith(PREFIX)) {
      throw new PasswordHashFormatException(
          "envelope marker '$pwh$' is missing or misplaced");
    }

    String body = encoded.substring(PREFIX.length());
    if (body.isEmpty() || body.charAt(0) != FIELD_SEPARATOR) {
      throw new PasswordHashFormatException(
          "envelope marker is not followed by a field separator");
    }
    body = body.substring(1);
    String[] tokens = body.split("\\" + FIELD_SEPARATOR, -1);

    Integer formatVersionWire = null;
    String credentialTypeRaw = null;
    String algorithm = null;
    String providerId = null;
    Integer policyVersion = null;
    Optional<String> pepperKeyId = Optional.empty();
    boolean pepperSeen = false;
    String parametersRaw = null;
    String innerHash = null;

    for (int i = 0; i < tokens.length; i++) {
      String token = tokens[i];
      if (token.isEmpty()) {
        throw new PasswordHashFormatException(
            "empty field at envelope position " + i);
      }
      int eq = token.indexOf('=');
      if (eq <= 0) {
        throw new PasswordHashFormatException(
            "malformed field at envelope position " + i);
      }
      String key = token.substring(0, eq);
      String value = token.substring(eq + 1);
      switch (key) {
        case FIELD_VERSION:
          if (formatVersionWire != null) {
            throw duplicate(key);
          }
          formatVersionWire = parseInt(value, key);
          break;
        case FIELD_CREDENTIAL_TYPE:
          if (credentialTypeRaw != null) {
            throw duplicate(key);
          }
          credentialTypeRaw = value;
          break;
        case FIELD_ALGORITHM:
          if (algorithm != null) {
            throw duplicate(key);
          }
          algorithm = value;
          break;
        case FIELD_PROVIDER:
          if (providerId != null) {
            throw duplicate(key);
          }
          providerId = value;
          break;
        case FIELD_POLICY_VERSION:
          if (policyVersion != null) {
            throw duplicate(key);
          }
          policyVersion = parseInt(value, key);
          break;
        case FIELD_PEPPER_KEY_ID:
          if (pepperSeen) {
            throw duplicate(key);
          }
          pepperSeen = true;
          if (value.isBlank()) {
            throw new PasswordHashFormatException(
                "pepper key id field is empty");
          }
          pepperKeyId = Optional.of(value);
          break;
        case FIELD_PARAMETERS:
          if (parametersRaw != null) {
            throw duplicate(key);
          }
          parametersRaw = value;
          break;
        case FIELD_INNER_HASH:
          if (innerHash != null) {
            throw duplicate(key);
          }
          innerHash = value;
          break;
        default:
          throw new PasswordHashFormatException(
              "unknown envelope field name");
      }
    }

    if (formatVersionWire == null) {
      throw missing(FIELD_VERSION);
    }
    if (credentialTypeRaw == null) {
      throw missing(FIELD_CREDENTIAL_TYPE);
    }
    if (algorithm == null) {
      throw missing(FIELD_ALGORITHM);
    }
    if (providerId == null) {
      throw missing(FIELD_PROVIDER);
    }
    if (policyVersion == null) {
      throw missing(FIELD_POLICY_VERSION);
    }
    if (parametersRaw == null) {
      throw missing(FIELD_PARAMETERS);
    }
    if (innerHash == null) {
      throw missing(FIELD_INNER_HASH);
    }

    PasswordHashFormatVersion formatVersion =
        PasswordHashFormatVersion.fromWireValue(formatVersionWire);

    CredentialType credentialType;
    try {
      credentialType = CredentialType.valueOf(credentialTypeRaw);
    } catch (IllegalArgumentException e) {
      throw new PasswordHashFormatException(
          "unknown credential type discriminator");
    }

    Map<String, String> parameters = parseParameters(parametersRaw);

    PasswordHashEnvelope envelope;
    try {
      envelope = new PasswordHashEnvelope(
          formatVersion,
          credentialType,
          algorithm,
          providerId,
          policyVersion,
          pepperKeyId,
          parameters,
          innerHash
      );
    } catch (IllegalArgumentException | NullPointerException e) {
      throw new PasswordHashFormatException(
          "envelope field rejected by invariant: " + e.getMessage());
    }
    return new PasswordHashRecord(encoded, envelope);
  }

  private static void appendField(StringBuilder sb, String key, String value) {
    sb.append(FIELD_SEPARATOR).append(key).append('=').append(value);
  }

  private static String joinParameters(Map<String, String> parameters) {
    if (parameters.isEmpty()) {
      return "";
    }
    StringBuilder sb = new StringBuilder();
    boolean first = true;
    for (Map.Entry<String, String> e : parameters.entrySet()) {
      if (!first) {
        sb.append(PARAM_SEPARATOR);
      }
      sb.append(e.getKey()).append('=').append(e.getValue());
      first = false;
    }
    return sb.toString();
  }

  private static Map<String, String> parseParameters(String raw) {
    Map<String, String> result = new LinkedHashMap<>();
    if (raw.isEmpty()) {
      return result;
    }
    String[] entries = raw.split(",", -1);
    for (int i = 0; i < entries.length; i++) {
      String entry = entries[i];
      if (entry.isEmpty()) {
        throw new PasswordHashFormatException(
            "empty parameter entry at index " + i);
      }
      int eq = entry.indexOf('=');
      if (eq <= 0) {
        throw new PasswordHashFormatException(
            "malformed parameter entry at index " + i);
      }
      String key = entry.substring(0, eq);
      String value = entry.substring(eq + 1);
      rejectParameterKey(key);
      if (result.put(key, value) != null) {
        throw new PasswordHashFormatException(
            "duplicate parameter key");
      }
    }
    return result;
  }

  private static int parseInt(String value, String fieldName) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new PasswordHashFormatException(
          "field '" + fieldName + "' is not an integer");
    }
  }

  private static PasswordHashFormatException duplicate(String key) {
    return new PasswordHashFormatException(
        "duplicate envelope field: " + key);
  }

  private static PasswordHashFormatException missing(String key) {
    return new PasswordHashFormatException(
        "missing required envelope field: " + key);
  }

  private static void rejectSeparators(String value, String fieldName) {
    if (value.indexOf(FIELD_SEPARATOR) >= 0
        || value.indexOf(PARAM_SEPARATOR) >= 0) {
      throw new PasswordHashFormatException(
          "field '" + fieldName + "' contains a reserved separator");
    }
  }

  private static void rejectInnerHashSeparators(String value) {
    if (value.indexOf(FIELD_SEPARATOR) >= 0) {
      throw new PasswordHashFormatException(
          "innerHash contains a reserved separator");
    }
  }

  private static void rejectParameterKey(String key) {
    if (key.isEmpty()) {
      throw new PasswordHashFormatException("parameter key is empty");
    }
    if (key.indexOf(FIELD_SEPARATOR) >= 0
        || key.indexOf(PARAM_SEPARATOR) >= 0
        || key.indexOf('=') >= 0) {
      throw new PasswordHashFormatException(
          "parameter key contains a reserved character");
    }
  }

  private static void rejectParameterValue(String value) {
    if (value.indexOf(FIELD_SEPARATOR) >= 0
        || value.indexOf(PARAM_SEPARATOR) >= 0) {
      throw new PasswordHashFormatException(
          "parameter value contains a reserved separator");
    }
  }
}
