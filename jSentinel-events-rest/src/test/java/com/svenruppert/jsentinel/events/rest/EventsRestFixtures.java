package com.svenruppert.jsentinel.events.rest;

/*-
 * #%L
 * jSentinel Events — REST / SSE bridge
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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.api.PayloadHashAlgorithm;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.bus.ConsumePipeline;
import com.svenruppert.jsentinel.events.bus.PublishPipeline;
import com.svenruppert.jsentinel.events.codec.CanonicalJsonPayloadCodec;
import com.svenruppert.jsentinel.events.codec.RecordReflectionCanonicalizer;
import com.svenruppert.jsentinel.events.keys.InMemoryKeyManagement;
import com.svenruppert.jsentinel.events.producer.AllowListProducerPolicy;
import com.svenruppert.jsentinel.events.producer.JSentinelEventProducerPolicy;
import com.svenruppert.jsentinel.events.replay.InMemoryReplayStore;
import com.svenruppert.jsentinel.events.sequence.InMemorySequenceStore;
import com.svenruppert.jsentinel.events.sequence.SequenceValidator;
import com.svenruppert.jsentinel.events.sequence.SequenceViolationStrategy;
import com.svenruppert.jsentinel.events.signature.Ed25519SignatureAlgorithm;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithms;
import com.svenruppert.jsentinel.events.types.LoginSucceededEvent;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.time.Duration;
import java.time.Instant;

/** Real signing/verification wiring for the events-rest tests — no mocks. */
final class EventsRestFixtures {

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

  ConsumePipeline newConsumePipeline() {
    return new ConsumePipeline(keyManagement, SignatureAlgorithms.defaults(),
        new InMemoryReplayStore(), new InMemorySequenceStore(), new SequenceValidator(),
        SequenceViolationStrategy.REJECT, allowAll);
  }

  SignedJSentinelEventEnvelope signedEnvelope() {
    EventMetadata meta = EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        T0, JSentinelEventSeverity.INFO);
    return newPublishPipeline().toEnvelope(new LoginSucceededEvent(meta, "password"));
  }
}
