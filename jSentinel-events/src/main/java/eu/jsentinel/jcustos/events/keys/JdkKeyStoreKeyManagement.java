package eu.jsentinel.jcustos.events.keys;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Optional;

/**
 * JDK {@code KeyStore}-backed key management (Konzept §599). The simple
 * reference implementation: private keys load from a PKCS12 store, public keys
 * come from the stored certificates, {@code keyId} maps to a store alias, and a
 * designated current alias is used for signing. Rotation is achieved by
 * pointing a new instance at a new current alias — no API break.
 *
 * <p>Non-goals (Konzept §609): full secret management, HSM, Cloud-KMS. Those
 * can follow later behind the same SPI.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class JdkKeyStoreKeyManagement
    implements JCustosEventSigningKeyProvider, JCustosEventVerificationKeyResolver {

  private final KeyStore keyStore;
  private final char[] keyPassword;
  private final KeyId currentAlias;
  private final SignatureAlgorithm algorithm;

  /**
   * @param keyStore an already-loaded key store
   * @param keyPassword the password protecting private-key entries
   * @param currentAlias the alias used as the current signing key
   * @param algorithm the signature algorithm bound to the keys
   */
  public JdkKeyStoreKeyManagement(KeyStore keyStore, char[] keyPassword,
      KeyId currentAlias, SignatureAlgorithm algorithm) {
    this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
    this.keyPassword = Objects.requireNonNull(keyPassword, "keyPassword").clone();
    this.currentAlias = Objects.requireNonNull(currentAlias, "currentAlias");
    this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
  }

  /**
   * Loads a PKCS12 key store from a path. The store password may, in
   * production, be sourced from {@code app.eventbus.keystore.password}.
   *
   * @param path the {@code .p12} file
   * @param storePassword the store password
   * @param keyPassword the private-key password
   * @param currentAlias the current signing alias
   * @param algorithm the signature algorithm
   * @return a configured key-management instance
   */
  public static JdkKeyStoreKeyManagement loadPkcs12(Path path, char[] storePassword,
      char[] keyPassword, KeyId currentAlias, SignatureAlgorithm algorithm) {
    try (InputStream in = Files.newInputStream(path)) {
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(in, storePassword);
      return new JdkKeyStoreKeyManagement(store, keyPassword, currentAlias, algorithm);
    } catch (IOException | GeneralSecurityException e) {
      throw new KeyAccessException("Cannot load PKCS12 key store from " + path, e);
    }
  }

  @Override
  public KeyId currentKeyId() {
    return currentAlias;
  }

  @Override
  public PrivateKey currentSigningKey() {
    try {
      java.security.Key key = keyStore.getKey(currentAlias.value(), keyPassword);
      if (!(key instanceof PrivateKey privateKey)) {
        throw new KeyAccessException(
            "Alias " + currentAlias.value() + " is not a private-key entry", null);
      }
      return privateKey;
    } catch (GeneralSecurityException e) {
      throw new KeyAccessException("Cannot read signing key " + currentAlias.value(), e);
    }
  }

  @Override
  public SignatureAlgorithm currentAlgorithm() {
    return algorithm;
  }

  @Override
  public Optional<PublicKey> resolveVerificationKey(KeyId keyId) {
    Objects.requireNonNull(keyId, "keyId");
    try {
      Certificate certificate = keyStore.getCertificate(keyId.value());
      return Optional.ofNullable(certificate).map(Certificate::getPublicKey);
    } catch (GeneralSecurityException e) {
      throw new KeyAccessException("Cannot read verification key " + keyId.value(), e);
    }
  }

  @Override
  public KeyStatus keyStatus(KeyId keyId) {
    Objects.requireNonNull(keyId, "keyId");
    try {
      if (!keyStore.containsAlias(keyId.value())) {
        return KeyStatus.UNKNOWN;
      }
      Certificate certificate = keyStore.getCertificate(keyId.value());
      if (certificate instanceof X509Certificate x509) {
        try {
          x509.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
          return KeyStatus.EXPIRED;
        }
      }
      return keyId.equals(currentAlias)
          ? KeyStatus.ACTIVE
          : KeyStatus.ACCEPTED_FOR_VERIFICATION;
    } catch (GeneralSecurityException e) {
      throw new KeyAccessException("Cannot read key status " + keyId.value(), e);
    }
  }
}
