package eu.jsentinel.jcustos.audit.integrity.export;

/*-
 * #%L
 * jCustos Audit Integrity — contract testkit
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

import eu.jsentinel.jcustos.audit.integrity.api.AuditChainEntry;
import eu.jsentinel.jcustos.audit.integrity.chain.AuditChainAppender;
import eu.jsentinel.jcustos.audit.integrity.chain.InMemoryAuditChainStore;
import eu.jsentinel.jcustos.audit.integrity.ChainTestFixtures;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.keys.InMemoryKeyManagement;
import eu.jsentinel.jcustos.events.signature.EcdsaP256SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.Ed25519SignatureAlgorithm;
import eu.jsentinel.jcustos.events.signature.SignatureAlgorithms;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("SignedAuditBatch — sign/verify round-trip with real keys")
class SignedAuditBatchRoundtripTest {

  private static final KeyId AUDIT_KEY = KeyId.of("audit-key-1");

  private final InMemoryKeyManagement keys =
      new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), AUDIT_KEY);
  private final AuditBatchSigner signer =
      new AuditBatchSigner(keys, () -> ChainTestFixtures.AT);
  private final AuditBatchVerifier verifier =
      new AuditBatchVerifier(keys, SignatureAlgorithms.defaults());

  private List<AuditChainEntry> realChain(int length) {
    InMemoryAuditChainStore store = new InMemoryAuditChainStore();
    AuditChainAppender appender = new AuditChainAppender(store);
    for (int i = 0; i < length; i++) {
      appender.append("test/v1", ("payload-" + i).getBytes(StandardCharsets.UTF_8));
    }
    return store.read(0, length);
  }

  @Test
  @DisplayName("a signed range verifies Valid with only public material")
  void roundTrip() {
    List<AuditChainEntry> chain = realChain(5);
    SignedAuditBatch batch = signer.sign(chain);

    AuditBatchVerificationResult.Valid valid = assertInstanceOf(
        AuditBatchVerificationResult.Valid.class, verifier.verify(batch, chain));
    assertEquals(5, valid.entryCount());
    assertEquals(chain.get(4).entryHash(), valid.batchHeadHash());
  }

  @Test
  @DisplayName("a flipped signature byte fails as SignatureInvalid")
  void flippedSignatureByte() {
    List<AuditChainEntry> chain = realChain(3);
    SignedAuditBatch batch = signer.sign(chain);
    byte[] signature = batch.signature();
    signature[0] ^= 0x01;
    SignedAuditBatch tampered = new SignedAuditBatch(batch.fromIndex(),
        batch.toIndex(), batch.entryCount(), batch.firstPreviousHash(),
        batch.batchHeadHash(), batch.signedAt(), batch.keyId(),
        batch.signatureAlgorithm(), signature);

    assertInstanceOf(AuditBatchVerificationResult.SignatureInvalid.class,
        verifier.verify(tampered, chain));
  }

  @Test
  @DisplayName("a tampered interior entry is reported as ChainBroken before any signature check")
  void tamperedEntryBeatsSignature() {
    List<AuditChainEntry> chain = realChain(4);
    SignedAuditBatch batch = signer.sign(chain);
    List<AuditChainEntry> tampered = new ArrayList<>(chain);
    tampered.set(1, ChainTestFixtures.tampered(chain.get(1), payload -> {
      payload[0] ^= 0x01;
      return payload;
    }));

    AuditBatchVerificationResult.ChainBroken broken = assertInstanceOf(
        AuditBatchVerificationResult.ChainBroken.class,
        verifier.verify(batch, tampered));
    assertEquals(1, broken.cause().atIndex());
  }

  @Test
  @DisplayName("after rotation the old key still verifies; after revocation it does not")
  void rotationAndRevocation() {
    List<AuditChainEntry> chain = realChain(3);
    SignedAuditBatch batch = signer.sign(chain);

    keys.rotate(KeyId.of("audit-key-2"));
    assertInstanceOf(AuditBatchVerificationResult.Valid.class,
        verifier.verify(batch, chain),
        "a rotated-out key is ACCEPTED_FOR_VERIFICATION — history stays checkable");

    keys.revoke(AUDIT_KEY);
    assertInstanceOf(AuditBatchVerificationResult.KeyRevoked.class,
        verifier.verify(batch, chain));
  }

  @Test
  @DisplayName("a foreign resolver knows nothing about the signing key")
  void foreignResolver() {
    List<AuditChainEntry> chain = realChain(2);
    SignedAuditBatch batch = signer.sign(chain);
    InMemoryKeyManagement foreign =
        new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KeyId.of("other"));

    assertInstanceOf(AuditBatchVerificationResult.UnknownKey.class,
        new AuditBatchVerifier(foreign, SignatureAlgorithms.defaults())
            .verify(batch, chain));
  }

  @Test
  @DisplayName("a range mismatch between batch and entries is rejected")
  void rangeMismatch() {
    List<AuditChainEntry> chain = realChain(4);
    SignedAuditBatch batch = signer.sign(chain);

    assertInstanceOf(AuditBatchVerificationResult.RangeMismatch.class,
        verifier.verify(batch, chain.subList(0, 3)),
        "fewer entries than declared");
  }

  @Test
  @DisplayName("the signer rejects empty and non-contiguous ranges")
  void signerGuards() {
    assertThrows(IllegalArgumentException.class, () -> signer.sign(List.of()));
    List<AuditChainEntry> chain = realChain(4);
    List<AuditChainEntry> gapped = List.of(chain.get(0), chain.get(2));
    assertThrows(IllegalArgumentException.class, () -> signer.sign(gapped));
  }

  @Test
  @DisplayName("algorithm agility: the batch signature also works over ECDSA P-256")
  void ecdsaRoundTrip() {
    InMemoryKeyManagement ecdsaKeys =
        new InMemoryKeyManagement(new EcdsaP256SignatureAlgorithm(), KeyId.of("ecdsa-key"));
    AuditBatchSigner ecdsaSigner = new AuditBatchSigner(ecdsaKeys);
    List<AuditChainEntry> chain = realChain(3);

    SignedAuditBatch batch = ecdsaSigner.sign(chain);
    assertInstanceOf(AuditBatchVerificationResult.Valid.class,
        new AuditBatchVerifier(ecdsaKeys, SignatureAlgorithms.defaults())
            .verify(batch, chain));
  }
}
