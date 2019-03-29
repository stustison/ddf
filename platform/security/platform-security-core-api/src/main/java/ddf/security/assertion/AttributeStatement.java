package ddf.security.assertion;

import java.util.List;

public interface AttributeStatement {

  List<Attribute> getAttributes();

  void addAttribute(Attribute attribute);
}
