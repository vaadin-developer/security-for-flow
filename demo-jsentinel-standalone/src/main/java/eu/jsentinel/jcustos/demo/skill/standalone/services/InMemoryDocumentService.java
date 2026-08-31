package eu.jsentinel.jcustos.demo.skill.standalone.services;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Plain in-memory {@link DocumentService}. No security logic —
 * the surrounding {@code SecuredProxy.wrap(...)} handles it.
 */
public final class InMemoryDocumentService implements DocumentService {

  private final List<String> titles = new CopyOnWriteArrayList<>();

  public InMemoryDocumentService() {
    titles.add("welcome.md");
    titles.add("notes.md");
  }

  @Override
  public List<String> list() {
    return List.copyOf(titles);
  }

  @Override
  public void create(String title) {
    if (title != null && !title.isBlank()) titles.add(title);
  }

  @Override
  public void delete(String title) {
    titles.remove(title);
  }
}
