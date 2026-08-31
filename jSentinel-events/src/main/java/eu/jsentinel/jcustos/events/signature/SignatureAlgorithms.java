package eu.jsentinel.jcustos.events.signature;

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
import eu.jsentinel.jcustos.events.api.SignatureAlgorithmId;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.ServiceLoader;

/**
 * Registry that resolves a {@link SignatureAlgorithm} from a
 * {@link SignatureAlgorithmId}.
 *
 * <p>{@link #defaults()} returns a registry pre-wired with the two built-in
 * providers (Ed25519 + SHA256withECDSA). {@link #discover()} additionally
 * loads any third-party providers contributed through
 * {@link ServiceLoader}; on an id clash the discovered provider wins over the
 * built-ins, so a deployment can override an algorithm binding.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class SignatureAlgorithms {

  private final Map<SignatureAlgorithmId, SignatureAlgorithm> byId;

  private SignatureAlgorithms(Map<SignatureAlgorithmId, SignatureAlgorithm> byId) {
    this.byId = byId;
  }

  /**
   * @return a registry with only the two built-in providers
   */
  public static SignatureAlgorithms defaults() {
    Map<SignatureAlgorithmId, SignatureAlgorithm> map = new LinkedHashMap<>();
    register(map, new Ed25519SignatureAlgorithm());
    register(map, new EcdsaP256SignatureAlgorithm());
    return new SignatureAlgorithms(map);
  }

  /**
   * @return a registry seeded with the built-ins, then overlaid with any
   *     {@link ServiceLoader}-discovered providers
   */
  public static SignatureAlgorithms discover() {
    Map<SignatureAlgorithmId, SignatureAlgorithm> map = new LinkedHashMap<>();
    register(map, new Ed25519SignatureAlgorithm());
    register(map, new EcdsaP256SignatureAlgorithm());
    for (SignatureAlgorithm provider : ServiceLoader.load(SignatureAlgorithm.class)) {
      register(map, provider);
    }
    return new SignatureAlgorithms(map);
  }

  private static void register(Map<SignatureAlgorithmId, SignatureAlgorithm> map,
      SignatureAlgorithm provider) {
    map.put(provider.id(), provider);
  }

  /**
   * @param id the algorithm identifier
   * @return the matching provider, if registered
   */
  public Optional<SignatureAlgorithm> find(SignatureAlgorithmId id) {
    return Optional.ofNullable(byId.get(Objects.requireNonNull(id, "id")));
  }

  /**
   * @param id the algorithm identifier
   * @return the matching provider
   * @throws IllegalArgumentException if no provider is registered for the id
   */
  public SignatureAlgorithm require(SignatureAlgorithmId id) {
    return find(id).orElseThrow(() ->
        new IllegalArgumentException("No SignatureAlgorithm registered for id " + id.value()));
  }

  /**
   * @return the number of registered providers
   */
  public int size() {
    return byId.size();
  }
}
