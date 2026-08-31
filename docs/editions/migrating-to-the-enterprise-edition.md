# Moving to the Enterprise Edition

If you used any of these nine modules up to and including **00.81.10**, they
were part of the community reactor. From **00.81.20** they ship as the
commercial jCustos Enterprise Edition.

- `jCustos-monitoring`
- `jCustos-audit-integrity`, `-testkit`, `-persistence-eclipsestore`
- `jCustos-events-webhook`, `-siem`, `-opentelemetry`, `-rest`
- `jCustos-events-persistence-eclipsestore`

## What changes: one line per dependency

Only the groupId moves. Artifact ids, Java packages, class names, wire formats,
metric names and audit-chain hash domains are **unchanged** — no imports to
rewrite, no stored data to migrate.

```xml
<!-- before -->
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-monitoring</artifactId>
</dependency>

<!-- from 00.81.20 -->
<dependency>
  <groupId>eu.jsentinel.jcustos.enterprise</groupId>
  <artifactId>jCustos-monitoring</artifactId>
</dependency>
```

Add the repository and the credentials that came with your licence:

```xml
<repository>
  <id>jsentinel-sensitive</id>
  <url>https://repo.jsentinel.eu/sensitive</url>
</repository>
```

```xml
<!-- ~/.m2/settings.xml -->
<server>
  <id>jsentinel-sensitive</id>
  <username>your-licence-user</username>
  <password>your-licence-token</password>
</server>
```

## Staying on the free edition

The 00.81.10 releases of these modules remain on Maven Central under the EUPL
and keep working. They will not receive further development there.

If you would rather drop them: they attach to the community core purely through
SPIs, so removing the dependency removes the feature and nothing else. The event
bus, signed envelopes, audit events and the whole identity stack are unaffected
— they are and remain part of the free edition.

## Getting a licence

https://jsentinel.eu/licence/enterprise
