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
 * A rotated refresh token was replayed — the family was revoked (RFC 9700
 * §4.13.2 reuse-detection, V00.77). This is a security signal: a stolen refresh
 * token is the most likely cause. The payload is a non-secret family identifier
 * (a hash), never a token.
 *
 * @param metadata variable per-instance metadata
 * @param familyId the non-secret refresh-token family identifier
 * @since 00.77.00
 */
@ExperimentalJCustosApi
public record RefreshTokenReuseDetectedEvent(EventMetadata metadata, String familyId)
    implements JCustosEvent {

  public static final EventType TYPE = EventType.of("RefreshTokenReuseDetected");

  public RefreshTokenReuseDetectedEvent {
    Objects.requireNonNull(metadata, "metadata");
    Objects.requireNonNull(familyId, "familyId");
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
