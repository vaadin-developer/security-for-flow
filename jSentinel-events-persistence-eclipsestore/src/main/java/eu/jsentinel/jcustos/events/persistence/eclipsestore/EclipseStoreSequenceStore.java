package eu.jsentinel.jcustos.events.persistence.eclipsestore;

/*-
 * #%L
 * jSentinel Events — Eclipse-Store persistence
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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import eu.jsentinel.jcustos.events.sequence.JSentinelEventSequenceStore;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Eclipse-Store-backed {@link JSentinelEventSequenceStore}. The per-{@code
 * (tenant, producer)} counter survives restart; updates are atomic via the
 * storage write lock (Konzept §1072, §322).
 *
 * <p>R03: the persisted composite key is length-prefix framed (see
 * {@link #framedKey(TenantId, EventProducerId)}) so that {@code '|'} content
 * inside a tenant or producer id can no longer alias two scopes onto one
 * counter. Legacy raw {@code tenant|producer} keys are rewritten at open by
 * {@link #migrateLegacySequenceKeys(EmbeddedStorageManager, EventStorageRoot)}.
 */
final class EclipseStoreSequenceStore implements JSentinelEventSequenceStore {

  /**
   * Schema marker in front of every framed key. Not needed for injectivity —
   * it exists so the migration at open can tell framed keys from legacy raw
   * keys without guessing (R03).
   */
  private static final String KEY_SCHEMA_PREFIX = "v2:";
  private static final char KEY_SEPARATOR = '|';

  private final EclipseStoreEventStorage storage;

  EclipseStoreSequenceStore(EclipseStoreEventStorage storage) {
    this.storage = storage;
  }

  /**
   * Builds the persisted composite key for a {@code (tenant, producer)} scope
   * with length-prefixed framing:
   * {@code v2:<utf8-byte-length>:<tenant>|<utf8-byte-length>:<producer>}.
   *
   * <p>R03 — injectivity: the previous raw {@code tenant + '|' + producer}
   * concatenation was collidable because both ids are free-form non-blank
   * strings that may themselves contain {@code '|'}, so ("a|b", "c") and
   * ("a", "b|c") aliased one counter. The explicit UTF-8 byte length fixes the
   * extent of the tenant segment before the separator is read, so no content
   * of either id can shift the segment boundary — two distinct
   * {@code (tenant, producer)} tuples always produce distinct keys. Byte
   * lengths match the framing convention of {@code EnvelopeSignatureBase} in
   * jSentinel-events.
   */
  private static String framedKey(TenantId tenantId, EventProducerId producerId) {
    return framedKey(
        Objects.requireNonNull(tenantId, "tenantId").value(),
        Objects.requireNonNull(producerId, "producerId").value());
  }

  /** Raw-string core of {@link #framedKey(TenantId, EventProducerId)}; also used by the migration. */
  private static String framedKey(String tenant, String producer) {
    return KEY_SCHEMA_PREFIX
        + utf8Length(tenant) + ':' + tenant
        + KEY_SEPARATOR + utf8Length(producer) + ':' + producer;
  }

  private static int utf8Length(String value) {
    return value.getBytes(StandardCharsets.UTF_8).length;
  }

  /**
   * R03 migration-at-open (mirrors {@code migrateResolvedDeadLetters}):
   * rewrites legacy raw {@code tenant|producer} sequence keys to the framed
   * {@code v2:} format. Called by {@code EclipseStoreEventStorage.openAt}
   * under the storage write lock, exactly once per open; idempotent across
   * reopens — framed keys are recognized by {@link #isFramedKey(String)} and
   * skipped, and an unchanged map is not re-stored.
   *
   * <p>A legacy key containing exactly one {@code '|'} splits unambiguously
   * into its original {@code (tenant, producer)} pair and is rewritten. A
   * legacy key with two or more {@code '|'} is genuinely ambiguous — e.g.
   * {@code a|b|c} may have been written by ("a|b", "c"), by ("a", "b|c"), or
   * interleaved by both — so no rewrite can be proven correct. Such keys stay
   * in place under their legacy key (the counter they carry is potentially the
   * merge of several scopes anyway, which is exactly the R03 defect) and are
   * reported per open via WARN {@code events-persistence/sequence-key-ambiguous};
   * the affected scopes start fresh framed counters on their next write.
   *
   * <p>Accepted residual corner: a legacy raw key that byte-identically
   * satisfies the full framed grammar (its tenant would have to start with
   * {@code "v2:<digits>:"} and the whole key parse with exact byte lengths) is
   * indistinguishable from a framed key by inspection and is left as-is.
   */
  static void migrateLegacySequenceKeys(EmbeddedStorageManager manager, EventStorageRoot root) {
    Map<String, Long> sequences = root.sequences;
    if (sequences.isEmpty()) {
      return;
    }
    boolean changed = false;
    for (String legacyKey : List.copyOf(sequences.keySet())) {
      if (isFramedKey(legacyKey)) {
        continue;
      }
      int first = legacyKey.indexOf(KEY_SEPARATOR);
      int last = legacyKey.lastIndexOf(KEY_SEPARATOR);
      if (first <= 0 || first != last || last == legacyKey.length() - 1) {
        HasLogger.staticLogger().warn(
            "events-persistence/sequence-key-ambiguous: legacy sequence key '{}' does not "
                + "split unambiguously into (tenant, producer); left under its legacy key",
            LogFieldScrubber.scrub(legacyKey));
        continue;
      }
      String framed = framedKey(legacyKey.substring(0, first), legacyKey.substring(first + 1));
      if (sequences.containsKey(framed)) {
        HasLogger.staticLogger().warn(
            "events-persistence/sequence-key-ambiguous: legacy sequence key '{}' collides "
                + "with an already-present framed key; left under its legacy key",
            LogFieldScrubber.scrub(legacyKey));
        continue;
      }
      sequences.put(framed, sequences.remove(legacyKey));
      changed = true;
    }
    if (changed) {
      manager.store(sequences);
    }
  }

  /**
   * Full-grammar check whether {@code key} is a framed {@code v2:} key:
   * schema marker, then two length-prefixed segments joined by {@code '|'},
   * with canonical decimal byte lengths (no leading zeros, at least one byte —
   * tenant and producer ids are non-blank) and the second segment ending
   * exactly at the end of the key.
   */
  private static boolean isFramedKey(String key) {
    if (!key.startsWith(KEY_SCHEMA_PREFIX)) {
      return false;
    }
    byte[] bytes = key.getBytes(StandardCharsets.UTF_8);
    int afterTenant = skipFramedSegment(bytes, KEY_SCHEMA_PREFIX.length());
    if (afterTenant < 0 || afterTenant >= bytes.length || bytes[afterTenant] != KEY_SEPARATOR) {
      return false;
    }
    int afterProducer = skipFramedSegment(bytes, afterTenant + 1);
    return afterProducer == bytes.length;
  }

  /**
   * Parses one {@code <utf8-byte-length>:<value>} segment starting at
   * {@code offset} and returns the index just past the value bytes, or
   * {@code -1} if the segment is malformed (no digits, leading zero,
   * missing {@code ':'}, zero or overrunning length).
   */
  private static int skipFramedSegment(byte[] bytes, int offset) {
    int i = offset;
    long length = 0;
    int digits = 0;
    while (i < bytes.length && bytes[i] >= '0' && bytes[i] <= '9') {
      length = length * 10 + (bytes[i] - '0');
      if (length > Integer.MAX_VALUE) {
        return -1;
      }
      digits++;
      i++;
    }
    if (digits == 0 || i >= bytes.length || bytes[i] != ':') {
      return -1;
    }
    if (length == 0 || (digits > 1 && bytes[offset] == '0')) {
      return -1;
    }
    long end = i + 1 + length;
    return end > bytes.length ? -1 : (int) end;
  }

  @Override
  public Optional<EventSequence> lastSequence(TenantId tenantId, EventProducerId producerId) {
    String key = framedKey(tenantId, producerId);
    storage.lock().readLock().lock();
    try {
      return Optional.ofNullable(storage.root().sequences.get(key)).map(EventSequence::of);
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void updateSequence(TenantId tenantId, EventProducerId producerId,
      EventSequence sequence) {
    Objects.requireNonNull(sequence, "sequence");
    String key = framedKey(tenantId, producerId);
    storage.lock().writeLock().lock();
    try {
      Map<String, Long> sequences = storage.root().sequences;
      sequences.put(key, sequence.value());
      storage.manager().store(sequences);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  // R011: the whole read-advance-write runs under the storage write lock, so two
  // publishers for the same scope can never reserve the same sequence.
  @Override
  public EventSequence reserveNext(TenantId tenantId, EventProducerId producerId) {
    String key = framedKey(tenantId, producerId);
    storage.lock().writeLock().lock();
    try {
      Map<String, Long> sequences = storage.root().sequences;
      Long last = sequences.get(key);
      EventSequence next = last == null ? EventSequence.FIRST : EventSequence.of(last).next();
      sequences.put(key, next.value());
      storage.manager().store(sequences);
      return next;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  // R016: the consume-side compare-and-advance runs the read-compare-commit under
  // the storage write lock, so a read-validate-commit cannot lose a race to a
  // concurrent advance (lost update / monotonicity break).
  @Override
  public boolean compareAndAdvance(TenantId tenantId, EventProducerId producerId,
      Optional<EventSequence> expectedLast, EventSequence newSequence) {
    Objects.requireNonNull(expectedLast, "expectedLast");
    Objects.requireNonNull(newSequence, "newSequence");
    String key = framedKey(tenantId, producerId);
    storage.lock().writeLock().lock();
    try {
      Map<String, Long> sequences = storage.root().sequences;
      Optional<EventSequence> current =
          Optional.ofNullable(sequences.get(key)).map(EventSequence::of);
      if (!current.equals(expectedLast)) {
        return false;
      }
      sequences.put(key, newSequence.value());
      storage.manager().store(sequences);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
