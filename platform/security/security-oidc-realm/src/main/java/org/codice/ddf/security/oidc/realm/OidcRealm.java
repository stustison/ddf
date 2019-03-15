package org.codice.ddf.security.oidc.realm;

import com.nimbusds.jwt.JWT;
import ddf.security.assertion.SecurityAssertion;
import ddf.security.assertion.jwt.impl.SecurityAssertionJwt;
import java.security.Principal;
import java.util.List;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.codice.ddf.security.handler.api.OidcAuthenticationToken;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcRealm extends AuthenticatingRealm {

  private static final Logger LOGGER = LoggerFactory.getLogger(OidcRealm.class);

  private List<String> usernameAttributeList;

  /** Determine if the supplied token is supported by this realm. */
  @Override
  public boolean supports(AuthenticationToken token) {
    boolean supported =
        token != null && token.getCredentials() != null && token instanceof OidcAuthenticationToken;

    if (supported) {
      LOGGER.debug("Token {} is supported by {}.", token.getClass(), OidcRealm.class.getName());
    } else if (token != null) {
      LOGGER.debug("Token {} is not supported by {}.", token.getClass(), OidcRealm.class.getName());
    } else {
      LOGGER.debug("The supplied authentication token is null. Sending back not supported.");
    }

    return supported;
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
      throws AuthenticationException {
    OidcAuthenticationToken oidcAuthenticationToken = (OidcAuthenticationToken) authenticationToken;
    OidcCredentials token = (OidcCredentials) oidcAuthenticationToken.getCredentials();

    SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo();
    SimplePrincipalCollection principals = createPrincipalFromJwt(token.getIdToken());
    simpleAuthenticationInfo.setPrincipals(principals);
    simpleAuthenticationInfo.setCredentials(token);

    return simpleAuthenticationInfo;
  }

  private SimplePrincipalCollection createPrincipalFromJwt(JWT token) {
    SimplePrincipalCollection principals = new SimplePrincipalCollection();
    SecurityAssertion securityAssertion = null;
    try {
      securityAssertion = new SecurityAssertionJwt(token, usernameAttributeList);
      Principal principal = securityAssertion.getPrincipal();
      if (principal != null) {
        principals.add(principal.getName(), getName());
      }
    } catch (Exception e) {
      LOGGER.warn(
          "Encountered error while trying to get the Principal for the SecurityToken. Security functions may not work properly.",
          e);
    }
    if (securityAssertion != null) {
      principals.add(securityAssertion, getName());
    }
    return principals;
  }

  public List<String> getUsernameAttributeList() {
    return usernameAttributeList;
  }

  public void setUsernameAttributeList(List<String> usernameAttributeList) {
    this.usernameAttributeList = usernameAttributeList;
  }
}
