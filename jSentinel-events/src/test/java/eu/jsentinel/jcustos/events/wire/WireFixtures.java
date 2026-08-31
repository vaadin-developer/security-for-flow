package eu.jsentinel.jcustos.events.wire;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.events.bus.PublishPipeline;
import eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.events.keys.InMemoryKeyManagement;
import eu.jsentinel.jcustos.events.producer.AllowListProducerPolicy;
import eu.jsentinel.jcustos.events.producer.JSentinelEventProducerPolicy;
import eu.jsentinel.jcustos.events.replay.InMemoryReplayStore;
import eu.jsentinel.jcustos.events.sequence.InMemorySequenceStore;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Duration;
import java.time.Instant;

/** Real signing wiring for the wire-codec tests — no mocks. */
final class WireFixtures {

  static final Instant T0 = Instant.parse("2026-06-24T10:00:00Z");
  static final EventProducerId PRODUCER = EventProducerId.of("rest-service-primary");

  final InMemoryKeyManagement keyManagement =
      new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KeyId.of("eventbus-1"));
  final JSentinelEventProducerPolicy allowAll = AllowListProducerPolicy.builder()
      .allow(PRODUCER, LoginSucceededEvent.TYPE)
      .build();

  PublishPipeline newPublishPipeline() {
    return new PublishPipeline(keyManagement, new RecordReflectionCanonicalizer(),
        new CanonicalJsonPayloadCodec(), PayloadHashAlgorithm.SHA_256, PRODUCER,
        new InMemorySequenceStore(), new InMemoryReplayStore(), allowAll,
        Duration.ofMinutes(5), () -> T0);
  }

  SignedJSentinelEventEnvelope signedEnvelope() {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        T0, JSentinelEventSeverity.INFO);
    return newPublishPipeline().toEnvelope(new LoginSucceededEvent(meta, "password"));
  }
}
