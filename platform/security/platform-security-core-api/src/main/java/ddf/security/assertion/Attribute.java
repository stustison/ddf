package ddf.security.assertion;

import java.util.List;

public interface Attribute {

  String getName();

  void setName(String name);

  String getNameFormat();

  void setNameFormat(String nameFormat);

  List<String> getValues();

  void setValues(List<String> values);

  void addValue(String value);
}
