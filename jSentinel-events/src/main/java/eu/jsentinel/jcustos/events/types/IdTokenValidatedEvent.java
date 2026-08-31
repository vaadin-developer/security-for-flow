package eu.jsentinel.jcustos.events.types;

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
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventCategory;

import java.util.Objects;

/**
 * An OIDC ID token validated successfully (V00.78). Non-secret payload: the issuer
 * only — never the token or its claims.
 *
 * @param metadata variable per-instance metadata
 * @param issuer   the OIDC issuer that minted the ID token
 * @since 00.78.00
 */
@ExperimentalJCustosApi
public record IdTokenValidatedEvent(EventMetadata metadata, String issuer) implements JCustosEvent {

  public static final EventType TYPE = EventType.of("IdTokenValidated");

  public IdTokenValidatedEvent {
    Objects.requireNonNull(metadata, "metadata");
    Objects.requireNonNull(issuer, "issuer");
  }

  @Override
  public EventType eventType() {
    return TYPE;
  }

  @Override
  public JCustosEventCategory category() {
    return JCustosEventCategory.TOKEN;
  }
}
