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
package eu.jsentinel.jcustos.oauth2;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.security.KeyStore;
import java.util.Objects;

/**
 * Client-side mTLS material for OAuth2 mutual-TLS client authentication (V00.79,
 * RFC 8705): the {@link KeyStore} holding the client certificate + private key, its
 * password, and the {@code alias} under which the client key lives. jCustos does not
 * load this from a hardware token / OS keychain — the consumer pre-loads the
 * {@code KeyStore} and passes it here (Konzept §4.5).
 *
 * <p>mTLS is NOT a {@code ClientAuthentication} variant: it operates at the TLS layer,
 * not as a token-endpoint parameter. {@link MutualTls#sslContext} turns this config into
 * an {@code SSLContext} for the {@code HttpClient} that {@code HttpTokenEndpointClient}
 * consumes.
 *
 * @since 00.79.20
 */
@ExperimentalJCustosApi
public record MutualTlsClientConfig(KeyStore keyStore, char[] password, String alias) {

  public MutualTlsClientConfig {
    Objects.requireNonNull(keyStore, "keyStore");
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(alias, "alias");
    if (alias.isBlank()) {
      throw new IllegalArgumentException("alias must not be blank");
    }
    password = password.clone();
  }

  @Override
  public char[] password() {
    return password.clone();
  }
}
