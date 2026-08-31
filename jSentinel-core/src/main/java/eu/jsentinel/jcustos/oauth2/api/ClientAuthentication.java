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
package eu.jsentinel.jcustos.oauth2.api;

import eu.jsentinel.jcustos.credential.secret.SecretValue;
import eu.jsentinel.jcustos.jwt.api.JwtSigningKey;

import java.time.Duration;
import java.util.Objects;

/**
 * How the RP authenticates to the token endpoint (RFC 6749 §2.3 + RFC 7523,
 * V00.77). A pure data type — the {@code jSentinel-oauth2} HTTP module
 * interprets it (Basic header / body fields / signed client assertion), so this
 * stays HTTP- and JOSE-free. Secret material is held in {@link SecretValue} /
 * {@link JwtSigningKey} and never logged.
 *
 * @since 00.77.00
 */
public sealed interface ClientAuthentication
    permits ClientAuthentication.ClientSecretBasic, ClientAuthentication.ClientSecretPost,
            ClientAuthentication.ClientSecretJwt, ClientAuthentication.PrivateKeyJwt,
            ClientAuthentication.NoneAuthentication {

  /** @return the OAuth2 {@code client_id}. */
  String clientId();

  /** RFC 6749 §2.3.1 — credentials in the HTTP Basic {@code Authorization} header. */
  record ClientSecretBasic(String clientId, SecretValue secret) implements ClientAuthentication {
    public ClientSecretBasic {
      Objects.requireNonNull(clientId, "clientId");
      Objects.requireNonNull(secret, "secret");
    }
  }

  /** RFC 6749 §2.3.1 — credentials as {@code client_id} / {@code client_secret} form fields. */
  record ClientSecretPost(String clientId, SecretValue secret) implements ClientAuthentication {
    public ClientSecretPost {
      Objects.requireNonNull(clientId, "clientId");
      Objects.requireNonNull(secret, "secret");
    }
  }

  /** RFC 7523 — an HMAC ({@code client_secret_jwt}) client assertion. */
  record ClientSecretJwt(String clientId, SecretValue secret, Duration assertionLifetime)
      implements ClientAuthentication {
    public ClientSecretJwt {
      Objects.requireNonNull(clientId, "clientId");
      Objects.requireNonNull(secret, "secret");
      Objects.requireNonNull(assertionLifetime, "assertionLifetime");
    }
  }

  /** RFC 7523 — an asymmetrically-signed ({@code private_key_jwt}) client assertion. */
  record PrivateKeyJwt(String clientId, JwtSigningKey signingKey, Duration assertionLifetime)
      implements ClientAuthentication {
    public PrivateKeyJwt {
      Objects.requireNonNull(clientId, "clientId");
      Objects.requireNonNull(signingKey, "signingKey");
      Objects.requireNonNull(assertionLifetime, "assertionLifetime");
    }
  }

  /** Public client (no secret) — only valid together with PKCE. */
  record NoneAuthentication(String clientId) implements ClientAuthentication {
    public NoneAuthentication {
      Objects.requireNonNull(clientId, "clientId");
    }
  }
}
