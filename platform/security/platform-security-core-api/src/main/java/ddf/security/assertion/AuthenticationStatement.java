package ddf.security.assertion;

import org.joda.time.DateTime;

public interface AuthenticationStatement {

  DateTime getAuthnInstant();

  void setAuthnInstant(DateTime authnInstant);

  String getSessionIndex();

  void setSessionIndex(String sessionIndex);

  DateTime getSessionNotOnOrAfter();

  void setSessionNotOnOrAfter(DateTime sessionNotOnOrAfter);

  String getAuthnContextClassRef();

  void setAuthnContextClassRef(String authnContextClassRef);
}
