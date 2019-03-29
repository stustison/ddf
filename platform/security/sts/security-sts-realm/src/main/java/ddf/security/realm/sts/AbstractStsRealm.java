/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package ddf.security.realm.sts;

import com.google.common.base.Splitter;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.hash.Hashing;
import ddf.security.PropertiesLoader;
import ddf.security.Subject;
import ddf.security.assertion.SecurityAssertion;
import ddf.security.assertion.saml.impl.SecurityAssertionSaml;
import ddf.security.common.SecurityTokenHolder;
import ddf.security.common.audit.SecurityLogger;
import ddf.security.http.SessionFactory;
import ddf.security.service.SecurityManager;
import ddf.security.service.SecurityServiceException;
import ddf.security.sts.client.configuration.STSClientConfiguration;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.bus.CXFBusFactory;
import org.apache.cxf.bus.spring.SpringBusFactory;
import org.apache.cxf.rs.security.saml.sso.SAMLProtocolResponseValidator;
import org.apache.cxf.staxutils.W3CDOMStreamWriter;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.cxf.ws.security.tokenstore.SecurityToken;
import org.apache.cxf.ws.security.trust.STSClient;
import org.apache.cxf.ws.security.trust.STSUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.SamlAssertionValidator;
import org.apache.wss4j.dom.validate.Validator;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.codice.ddf.configuration.PropertyResolver;
import org.codice.ddf.platform.filter.AuthenticationFailureException;
import org.codice.ddf.platform.util.XMLUtils;
import org.codice.ddf.security.handler.api.BaseAuthenticationToken;
import org.codice.ddf.security.handler.api.SAMLAuthenticationToken;
import org.codice.ddf.security.handler.api.STSAuthenticationToken;
import org.codice.ddf.security.policy.context.ContextPolicy;
import org.codice.ddf.security.policy.context.ContextPolicyManager;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSSerializer;

public abstract class AbstractStsRealm extends AuthenticatingRealm
    implements STSClientConfiguration {
  private static final Logger LOGGER = (LoggerFactory.getLogger(AbstractStsRealm.class));

  private static final String NAME = AbstractStsRealm.class.getSimpleName();

  private static final String ADDRESSING_NAMESPACE = "http://www.w3.org/2005/08/addressing";

  private static final Splitter SPLITTER = Splitter.on(',').trimResults().omitEmptyStrings();

  private static final String DDF_AUTHENTICATION_TOKEN = "ddf.security.token";

  private static final String SAML_PROPERTY_KEY = ddf.security.SecurityConstants.SECURITY_TOKEN_KEY;

  private static final int DEFAULT_EXPIRATION_TIME = 31;

  private static final ThreadLocal<DocumentBuilder> BUILDER =
      new ThreadLocal<DocumentBuilder>() {
        @Override
        protected DocumentBuilder initialValue() {
          try {
            return XML_UTILS.getSecureDocumentBuilder(true);
          } catch (ParserConfigurationException ex) {
            // This exception should not happen
            throw new IllegalArgumentException("Unable to create new DocumentBuilder", ex);
          }
        }
      };

  private static final XMLUtils XML_UTILS = XMLUtils.getInstance();

  private static SAMLObjectBuilder<Status> statusBuilder;

  private static SAMLObjectBuilder<StatusCode> statusCodeBuilder;

  private static SAMLObjectBuilder<StatusMessage> statusMessageBuilder;

  private static SAMLObjectBuilder<Response> responseBuilder;

  private static SAMLObjectBuilder<Issuer> issuerBuilder;

  private static XMLObjectBuilderFactory builderFactory =
      XMLObjectProviderRegistrySupport.getBuilderFactory();

  protected Bus bus;

  PropertyResolver address = null;

  String endpointName = null;

  String serviceName = null;

  String username = null;

  String password = null;

  String signatureUsername = null;

  String signatureProperties = null;

  String encryptionUsername = null;

  String encryptionProperties = null;

  String tokenUsername = null;

  String tokenProperties = null;

  List<String> claims = new ArrayList<>();

  private ContextPolicyManager contextPolicyManager;

  private SecurityManager securityManager;

  private Crypto signatureCrypto;

  private String assertionType = null;

  private String keyType = null;

  private String keySize = null;

  private Boolean useKey = null;

  private Validator assertionValidator = new SamlAssertionValidator();

  private Cache<Element, SecurityToken> cache =
      CacheBuilder.newBuilder().expireAfterAccess(1, TimeUnit.MINUTES).build();

  private SessionFactory sessionFactory;

  private int expirationTime = DEFAULT_EXPIRATION_TIME;

  public AbstractStsRealm() {
    this.bus = getBus();
    setCredentialsMatcher(new STSCredentialsMatcher());
  }

  public void setContextPolicyManager(ContextPolicyManager contextPolicyManager) {
    this.contextPolicyManager = contextPolicyManager;
  }

  /** Determine if the supplied token is supported by this realm. */
  @Override
  public boolean supports(AuthenticationToken token) {
    boolean supported = token != null && token.getCredentials() != null;
    //    if (token instanceof STSAuthenticationToken) {
    //      supported = supported && ((STSAuthenticationToken) token).isUseWssSts() ==
    // shouldHandleWss();
    //    }

    if (supported) {
      LOGGER.debug(
          "Token {} is supported by {}.", token.getClass(), AbstractStsRealm.class.getName());
    } else if (token != null) {
      LOGGER.debug(
          "Token {} is not supported by {}.", token.getClass(), AbstractStsRealm.class.getName());
    } else {
      LOGGER.debug("The supplied authentication token is null. Sending back not supported.");
    }

    return supported;
  }

  protected abstract boolean shouldHandleWss();

  /** Perform authentication based on the supplied token. */
  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) {
    Object credential;

    // perform validation
    if (token instanceof SAMLAuthenticationToken) {
      try {
        validateRequest((SAMLAuthenticationToken) token);
        credential = token.getCredentials();
      } catch (AuthenticationFailureException e) {
        String msg = "Unable to validate request's authentication.";
        LOGGER.info(msg);
        throw new AuthenticationException(msg, e);
      }
    } else if (token instanceof STSAuthenticationToken) {
      credential = ((STSAuthenticationToken) token).getCredentialsAsString();
    } else {
      credential = token.getCredentials().toString();
    }

    if (credential == null) {
      String msg =
          "Unable to authenticate credential.  A NULL credential was provided in the supplied authentication token. This may be due to an error with the SSO server that created the token.";
      LOGGER.info(msg);
      throw new AuthenticationException(msg);
    } else {
      // removed the credentials from the log message for now, I don't think we should be dumping
      // user/pass into log
      LOGGER.debug("Received credentials.");
    }

    SecurityToken securityToken;
    if (token instanceof SAMLAuthenticationToken && credential instanceof SecurityToken) {
      securityToken = renewSecurityToken((SecurityToken) credential);
    } else {
      securityToken = requestSecurityToken(credential);
    }

    LOGGER.debug("Creating token authentication information with SAML.");
    SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo();
    SimplePrincipalCollection principals = new SimplePrincipalCollection();
    SecurityAssertion assertion = new SecurityAssertionSaml(securityToken);
    principals.add(assertion.getPrincipal(), NAME);
    principals.add(assertion, NAME);
    simpleAuthenticationInfo.setPrincipals(principals);
    simpleAuthenticationInfo.setCredentials(credential);

    return simpleAuthenticationInfo;
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //// START LOGIN FILTER MIGRATION
  // ////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  private void validateRequest(SAMLAuthenticationToken token)
      throws AuthenticationFailureException {
    try {
      LOGGER.debug("Validating received SAML assertion.");

      SecurityToken securityToken;
      securityToken = (SecurityToken) token.getCredentials();

      // don't revalidate saved tokens
      if (!token.wasRetrievedFromReference()) {
        SamlAssertionWrapper assertion = new SamlAssertionWrapper(securityToken.getToken());

        // get the crypto junk
        Crypto crypto = getSignatureCrypto();
        Response samlResponse =
            createSamlResponse(
                token.getRequestURI(),
                assertion.getIssuerString(),
                createStatus(SAMLProtocolResponseValidator.SAML2_STATUSCODE_SUCCESS, null));

        BUILDER.get().reset();
        Document doc = BUILDER.get().newDocument();
        Element policyElement = OpenSAMLUtil.toDom(samlResponse, doc);
        doc.appendChild(policyElement);

        Credential credential = new Credential();
        credential.setSamlAssertion(assertion);

        RequestData requestData = new RequestData();
        requestData.setWsDocInfo(new WSDocInfo(samlResponse.getDOM().getOwnerDocument()));
        requestData.setSigVerCrypto(crypto);
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        requestData.setWssConfig(wssConfig);

        X509Certificate[] x509Certs = token.getX509Certs();
        requestData.setTlsCerts(x509Certs);

        validateHolderOfKeyConfirmation(assertion, x509Certs);

        if (assertion.isSigned()) {
          // Verify the signature
          WSSSAMLKeyInfoProcessor wsssamlKeyInfoProcessor =
              new WSSSAMLKeyInfoProcessor(requestData);
          assertion.verifySignature(wsssamlKeyInfoProcessor, crypto);

          assertion.parseSubject(
              new WSSSAMLKeyInfoProcessor(requestData),
              requestData.getSigVerCrypto(),
              requestData.getCallbackHandler());
        }

        // Validate the Assertion & verify trust in the signature
        assertionValidator.validate(credential, requestData);
      }
    } catch (SecurityServiceException e) {
      LOGGER.debug("Unable to get subject from SAML request.", e);
      throw new AuthenticationFailureException(e);
    } catch (WSSecurityException e) {
      LOGGER.debug("Unable to read/validate security token from request.", e);
      throw new AuthenticationFailureException(e);
    }
  }

  private Subject handleAuthenticationToken(
      HttpServletRequest httpRequest, BaseAuthenticationToken token)
      throws AuthenticationFailureException {

    Subject subject;
    HttpSession session = sessionFactory.getOrCreateSession(httpRequest);
    // if we already have an assertion inside the session and it has not expired, then use that
    // instead
    Object sessionToken = getSecurityToken(session, token.getRealm());

    if (sessionToken == null) {

      /*
       * The user didn't have a SAML token from a previous authentication, but they do have the
       * credentials to log in - perform that action here.
       */
      try {
        // login with the specified authentication credentials (AuthenticationToken)
        subject = securityManager.getSubject(token);

        for (Object principal : subject.getPrincipals().asList()) {
          if (principal instanceof SecurityAssertion) {
            if (LOGGER.isTraceEnabled()) {
              Element samlToken =
                  ((SecurityToken) ((SecurityAssertion) principal).getToken()).getToken();

              LOGGER.trace("SAML Assertion returned: {}", XML_UTILS.prettyFormat(samlToken));
            }
            SecurityToken securityToken =
                ((SecurityToken) ((SecurityAssertion) principal).getToken());
            addSamlToSession(httpRequest, token.getRealm(), securityToken);
          }
        }
      } catch (SecurityServiceException e) {
        LOGGER.debug("Unable to get subject from auth request.", e);
        throw new AuthenticationFailureException(e);
      }
    } else {
      LOGGER.trace("Creating SAML authentication token with session.");
      SAMLAuthenticationToken samlToken =
          new SAMLAuthenticationToken(null, session.getId(), token.getRealm());
      return handleAuthenticationToken(httpRequest, samlToken);
    }
    return subject;
  }

  private void validateHolderOfKeyConfirmation(
      SamlAssertionWrapper assertion, X509Certificate[] x509Certs) throws SecurityServiceException {
    List<String> confirmationMethods = assertion.getConfirmationMethods();
    boolean hasHokMethod = false;
    for (String method : confirmationMethods) {
      if (OpenSAMLUtil.isMethodHolderOfKey(method)) {
        hasHokMethod = true;
      }
    }

    if (hasHokMethod) {
      if (x509Certs != null && x509Certs.length > 0) {
        List<SubjectConfirmation> subjectConfirmations =
            assertion.getSaml2().getSubject().getSubjectConfirmations();
        for (SubjectConfirmation subjectConfirmation : subjectConfirmations) {
          if (OpenSAMLUtil.isMethodHolderOfKey(subjectConfirmation.getMethod())) {
            Element dom = subjectConfirmation.getSubjectConfirmationData().getDOM();
            Node keyInfo = dom.getFirstChild();
            Node x509Data = keyInfo.getFirstChild();
            Node dataNode = x509Data.getFirstChild();
            Node dataText = dataNode.getFirstChild();

            X509Certificate tlsCertificate = x509Certs[0];
            if (dataNode.getLocalName().equals("X509Certificate")) {
              String textContent = dataText.getTextContent();
              byte[] byteValue = Base64.getMimeDecoder().decode(textContent);
              try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert =
                    (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(byteValue));
                // check that the certificate is still valid
                cert.checkValidity();

                // HoK spec section 2.5:
                // relying party MUST ensure that the certificate bound to the assertion matches the
                // X.509 certificate in its possession.
                // Matching is done by comparing the base64-decoded certificates, or the hash values
                // of the base64-decoded certificates, byte-for-byte.
                // if the certs aren't the same, verify
                if (!tlsCertificate.equals(cert)) {
                  // verify that the cert was signed by the same private key as the TLS cert
                  cert.verify(tlsCertificate.getPublicKey());
                }
              } catch (CertificateException
                  | NoSuchAlgorithmException
                  | InvalidKeyException
                  | SignatureException
                  | NoSuchProviderException e) {
                throw new SecurityServiceException(
                    "Unable to validate Holder of Key assertion with certificate.");
              }

            } else if (dataNode.getLocalName().equals("X509SubjectName")) {
              String textContent = dataText.getTextContent();
              // HoK spec section 2.5:
              // relying party MUST ensure that the subject distinguished name (DN) bound to the
              // assertion matches the DN bound to the X.509 certificate.
              // If, however, the relying party does not trust the certificate issuer to issue such
              // a DN, the attesting entity is not confirmed and the relying party SHOULD disregard
              // the assertion.
              if (!tlsCertificate.getSubjectDN().getName().equals(textContent)) {
                throw new SecurityServiceException(
                    "Unable to validate Holder of Key assertion with subject DN.");
              }

            } else if (dataNode.getLocalName().equals("X509IssuerSerial")) {
              // we have no way to support this confirmation type so we have to throw an error
              throw new SecurityServiceException(
                  "Unable to validate Holder of Key assertion with issuer serial. NOT SUPPORTED");
            } else if (dataNode.getLocalName().equals("X509SKI")) {
              String textContent = dataText.getTextContent();
              byte[] tlsSKI = tlsCertificate.getExtensionValue("2.5.29.14");
              byte[] assertionSKI = Base64.getMimeDecoder().decode(textContent);
              if (tlsSKI != null && tlsSKI.length > 0) {
                ASN1OctetString tlsOs = ASN1OctetString.getInstance(tlsSKI);
                ASN1OctetString assertionOs = ASN1OctetString.getInstance(assertionSKI);
                SubjectKeyIdentifier tlsSubjectKeyIdentifier =
                    SubjectKeyIdentifier.getInstance(tlsOs.getOctets());
                SubjectKeyIdentifier assertSubjectKeyIdentifier =
                    SubjectKeyIdentifier.getInstance(assertionOs.getOctets());
                // HoK spec section 2.5:
                // relying party MUST ensure that the value bound to the assertion matches the
                // Subject Key Identifier (SKI) extension bound to the X.509 certificate.
                // Matching is done by comparing the base64-decoded SKI values byte-for-byte. If the
                // X.509 certificate does not contain an SKI extension,
                // the attesting entity is not confirmed and the relying party SHOULD disregard the
                // assertion.
                if (!Arrays.equals(
                    tlsSubjectKeyIdentifier.getKeyIdentifier(),
                    assertSubjectKeyIdentifier.getKeyIdentifier())) {
                  throw new SecurityServiceException(
                      "Unable to validate Holder of Key assertion with subject key identifier.");
                }
              } else {
                throw new SecurityServiceException(
                    "Unable to validate Holder of Key assertion with subject key identifier.");
              }
            }
          }
        }
      } else {
        throw new SecurityServiceException("Holder of Key assertion, must be used with 2-way TLS.");
      }
    }
  }

  /**
   * Creates the SAML response that we use for validation against the CXF code.
   *
   * @param inResponseTo
   * @param issuer
   * @param status
   * @return Response
   */
  private static Response createSamlResponse(String inResponseTo, String issuer, Status status) {
    if (responseBuilder == null) {
      responseBuilder =
          (SAMLObjectBuilder<Response>) builderFactory.getBuilder(Response.DEFAULT_ELEMENT_NAME);
    }
    Response response = responseBuilder.buildObject();

    response.setID(UUID.randomUUID().toString());
    response.setIssueInstant(new DateTime());
    response.setInResponseTo(inResponseTo);
    response.setIssuer(createIssuer(issuer));
    response.setStatus(status);
    response.setVersion(SAMLVersion.VERSION_20);

    return response;
  }

  /**
   * Creates the issuer object for the response.
   *
   * @param issuerValue
   * @return Issuer
   */
  private static Issuer createIssuer(String issuerValue) {
    if (issuerBuilder == null) {
      issuerBuilder =
          (SAMLObjectBuilder<Issuer>) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
    }
    Issuer issuer = issuerBuilder.buildObject();
    issuer.setValue(issuerValue);

    return issuer;
  }

  /**
   * Creates the status object for the response.
   *
   * @param statusCodeValue
   * @param statusMessage
   * @return Status
   */
  private static Status createStatus(String statusCodeValue, String statusMessage) {
    if (statusBuilder == null) {
      statusBuilder =
          (SAMLObjectBuilder<Status>) builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
    }
    if (statusCodeBuilder == null) {
      statusCodeBuilder =
          (SAMLObjectBuilder<StatusCode>)
              builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
    }
    if (statusMessageBuilder == null) {
      statusMessageBuilder =
          (SAMLObjectBuilder<StatusMessage>)
              builderFactory.getBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
    }

    Status status = statusBuilder.buildObject();

    StatusCode statusCode = statusCodeBuilder.buildObject();
    statusCode.setValue(statusCodeValue);
    status.setStatusCode(statusCode);

    if (statusMessage != null) {
      StatusMessage statusMessageObject = statusMessageBuilder.buildObject();
      statusMessageObject.setMessage(statusMessage);
      status.setStatusMessage(statusMessageObject);
    }

    return status;
  }

  /**
   * Returns a Crypto object initialized against the system signature properties.
   *
   * @return Crypto
   */
  private Crypto getSignatureCrypto() {
    if (signatureCrypto == null && signatureProperties != null) {
      Properties sigProperties = PropertiesLoader.loadProperties(signatureProperties);
      if (sigProperties == null) {
        LOGGER.trace("Cannot load signature properties using: {}", signatureProperties);
        return null;
      }
      ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
      Thread.currentThread().setContextClassLoader(AbstractStsRealm.class.getClassLoader());
      try {
        signatureCrypto = CryptoFactory.getInstance(sigProperties);
      } catch (WSSecurityException ex) {
        LOGGER.trace("Error in loading the signature Crypto object.", ex);
        return null;
      } finally {
        Thread.currentThread().setContextClassLoader(contextClassLoader);
      }
    }
    return signatureCrypto;
  }

  /**
   * Adds SAML assertion to HTTP session.
   *
   * @param httpRequest the http request object for this request
   * @param securityToken the SecurityToken object representing the SAML assertion
   */
  private void addSamlToSession(
      HttpServletRequest httpRequest, String realm, SecurityToken securityToken) {
    if (securityToken == null) {
      LOGGER.debug("Cannot add null security token to session.");
      return;
    }

    HttpSession session = sessionFactory.getOrCreateSession(httpRequest);
    Object sessionToken = getSecurityToken(session, realm);
    if (sessionToken == null) {
      addSecurityToken(session, realm, securityToken);
    }
    SecurityAssertion securityAssertion = new SecurityAssertionSaml(securityToken);
    SecurityLogger.audit(
        "Added SAML for user [{}] to session [{}]",
        securityAssertion.getPrincipal().getName(),
        Hashing.sha256().hashString(session.getId(), StandardCharsets.UTF_8).toString());
    int minutes = getExpirationTime();

    session.setMaxInactiveInterval(minutes * 60);
  }

  private void addSecurityToken(HttpSession session, String realm, SecurityToken token) {
    SecurityTokenHolder holder = (SecurityTokenHolder) session.getAttribute(SAML_PROPERTY_KEY);

    holder.addSecurityToken(realm, token);
  }

  private Object getSecurityToken(HttpSession session, String realm) {
    if (session.getAttribute(SAML_PROPERTY_KEY) == null) {
      LOGGER.debug("Security token holder missing from session. New session created improperly.");
      return null;
    }

    SecurityTokenHolder tokenHolder =
        ((SecurityTokenHolder) session.getAttribute(SAML_PROPERTY_KEY));

    SecurityToken token = (SecurityToken) tokenHolder.getSecurityToken(realm);

    if (token != null) {
      SecurityAssertionSaml assertion = new SecurityAssertionSaml(token);
      if (!assertion.isPresentlyValid()) {
        LOGGER.debug("Session SAML token is invalid.  Removing from session.");
        tokenHolder.remove(realm);
        return null;
      }
    }

    return token;
  }

  /**
   * Returns session expiration time in minutes.
   *
   * @return minutes for session expiration
   */
  public int getExpirationTime() {
    return expirationTime;
  }

  /**
   * Sets session expiration time in minutes
   *
   * @param expirationTime - time in minutes
   */
  public void setExpirationTime(int expirationTime) {
    // Sets expirationTime to the default if the provided value is less than 2
    if (expirationTime >= 2) {
      this.expirationTime = expirationTime;
    } else {
      LOGGER.info(
          "Session expiration time of {} minute(s) is invalid. It will be set to the default of {} minutes",
          expirationTime,
          DEFAULT_EXPIRATION_TIME);
      this.expirationTime = DEFAULT_EXPIRATION_TIME;
    }
  }

  public void setSessionFactory(SessionFactory sessionFactory) {
    this.sessionFactory = sessionFactory;
  }
  //////////////////////////////////////////////////////////////////////////////////////////////////////
  //// END LOGIN FILTER MIGRATION
  // //////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////////////////////////////////

  /**
   * Request a security token (SAML assertion) from the STS.
   *
   * @param authToken The subject the security token is being request for.
   * @return security token (SAML assertion)
   */
  protected SecurityToken requestSecurityToken(Object authToken) {
    SecurityToken token = null;
    String stsAddress = getAddress();

    try {
      LOGGER.debug("Requesting security token from STS at: {}.", stsAddress);

      ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
      Thread.currentThread().setContextClassLoader(AbstractStsRealm.class.getClassLoader());
      try {
        if (authToken != null) {
          LOGGER.debug("Telling the STS to request a security token on behalf of the auth token");
          STSClient stsClient = configureStsClient();

          stsClient.setWsdlLocation(stsAddress);
          stsClient.setOnBehalfOf(authToken);
          stsClient.setTokenType(getAssertionType());
          stsClient.setKeyType(getKeyType());
          stsClient.setKeySize(Integer.parseInt(getKeySize()));
          stsClient.setAllowRenewing(true);
          stsClient.setAllowRenewingAfterExpiry(true);
          token = stsClient.requestSecurityToken();
          LOGGER.debug("Finished requesting security token.");
        }
      } finally {
        Thread.currentThread().setContextClassLoader(contextClassLoader);
      }
    } catch (Exception e) {
      String msg = "Error requesting the security token from STS at: " + stsAddress + ".";
      LOGGER.debug(msg, e);
      throw new AuthenticationException(msg, e);
    }

    return token;
  }

  /**
   * Renew a security token (SAML assertion) from the STS.
   *
   * @param securityToken The token being renewed.
   * @return security token (SAML assertion)
   */
  protected SecurityToken renewSecurityToken(final SecurityToken securityToken) {
    String stsAddress = getAddress();

    try {
      LOGGER.debug("Renewing security token from STS at: {}.", stsAddress);

      if (securityToken != null) {
        synchronized (securityToken.getToken()) {
          return cache.get(
              securityToken.getToken(),
              () -> {
                LOGGER.debug(
                    "Telling the STS to renew a security token on behalf of the auth token");
                STSClient stsClient = configureStsClient();

                stsClient.setWsdlLocation(stsAddress);
                stsClient.setTokenType(getAssertionType());
                stsClient.setKeyType(getKeyType());
                stsClient.setKeySize(Integer.parseInt(getKeySize()));
                stsClient.setAllowRenewing(true);
                stsClient.setAllowRenewingAfterExpiry(true);
                SecurityToken token = stsClient.renewSecurityToken(securityToken);
                cache.put(securityToken.getToken(), token);
                LOGGER.debug("Finished renewing security token.");

                return token;
              });
        }
      } else {
        return null;
      }
    } catch (Exception e) {
      String msg = "Error renewing the security token from STS at: " + stsAddress + ".";
      LOGGER.debug(msg, e);
      throw new AuthenticationException(msg, e);
    }
  }

  /**
   * Logs the current STS client configuration.
   *
   * @param stsClient
   */
  private void logStsClientConfiguration(STSClient stsClient) {
    StringBuilder builder = new StringBuilder();

    builder.append("\nSTS Client configuration:\n");
    builder.append("STS WSDL location: " + stsClient.getWsdlLocation() + "\n");
    builder.append("STS service name: " + stsClient.getServiceQName() + "\n");
    builder.append("STS endpoint name: " + stsClient.getEndpointQName() + "\n");

    Map<String, Object> map = stsClient.getProperties();
    Set<Map.Entry<String, Object>> entries = map.entrySet();
    builder.append("\nSTS Client properties:\n");
    for (Map.Entry<String, Object> entry : entries) {
      builder.append("key: " + entry.getKey() + "; value: " + entry.getValue() + "\n");
    }

    LOGGER.debug("builder: {}", builder);
  }

  /** Helper method to setup STS Client. */
  protected Bus getBus() {
    BusFactory bf = new CXFBusFactory();
    Bus setBus = bf.createBus();
    SpringBusFactory.setDefaultBus(setBus);
    SpringBusFactory.setThreadDefaultBus(setBus);

    return setBus;
  }

  /**
   * Helper method to setup STS Client.
   *
   * @param stsClient
   */
  private void addStsProperties(STSClient stsClient) {
    Map<String, Object> map = new HashMap<>();

    String signaturePropertiesPath = getSignatureProperties();
    if (signaturePropertiesPath != null && !signaturePropertiesPath.isEmpty()) {
      LOGGER.debug("Setting signature properties on STSClient: {}", signaturePropertiesPath);
      Properties signatureProperties = PropertiesLoader.loadProperties(signaturePropertiesPath);
      map.put(SecurityConstants.SIGNATURE_PROPERTIES, signatureProperties);
    }

    String encryptionPropertiesPath = getEncryptionProperties();
    if (encryptionPropertiesPath != null && !encryptionPropertiesPath.isEmpty()) {
      LOGGER.debug("Setting encryption properties on STSClient: {}", encryptionPropertiesPath);
      Properties encryptionProperties = PropertiesLoader.loadProperties(encryptionPropertiesPath);
      map.put(SecurityConstants.ENCRYPT_PROPERTIES, encryptionProperties);
    }

    String stsPropertiesPath = getTokenProperties();
    if (stsPropertiesPath != null && !stsPropertiesPath.isEmpty()) {
      LOGGER.debug("Setting sts properties on STSClient: {}", stsPropertiesPath);
      Properties stsProperties = PropertiesLoader.loadProperties(stsPropertiesPath);
      map.put(SecurityConstants.STS_TOKEN_PROPERTIES, stsProperties);
    }

    LOGGER.debug("Setting callback handler on STSClient");
    // DDF-733 map.put(SecurityConstants.CALLBACK_HANDLER, new CommonCallbackHandler());

    LOGGER.debug("Setting STS TOKEN USE CERT FOR KEY INFO to \"true\"");
    map.put(SecurityConstants.STS_TOKEN_USE_CERT_FOR_KEYINFO, String.valueOf(getUseKey()));

    LOGGER.debug("Adding in realm information to the STSClient");
    map.put("CLIENT_REALM", "DDF");

    stsClient.setProperties(map);
  }

  /** Helper method to setup STS Client. */
  private STSClient configureBaseStsClient() {
    STSClient stsClient = new STSClient(bus);
    String stsAddress = getAddress();
    String stsServiceName = getServiceName();
    String stsEndpointName = getEndpointName();

    if (stsAddress != null) {
      LOGGER.debug("Setting WSDL location on STSClient: {}", stsAddress);
      stsClient.setWsdlLocation(stsAddress);
    }

    if (stsServiceName != null) {
      LOGGER.debug("Setting service name on STSClient: {}", stsServiceName);
      stsClient.setServiceName(stsServiceName);
    }

    if (stsEndpointName != null) {
      LOGGER.debug("Setting endpoint name on STSClient: {}", stsEndpointName);
      stsClient.setEndpointName(stsEndpointName);
    }

    LOGGER.debug("Setting addressing namespace on STSClient: {}", ADDRESSING_NAMESPACE);
    stsClient.setAddressingNamespace(ADDRESSING_NAMESPACE);

    return stsClient;
  }

  /** Helper method to setup STS Client. */
  protected STSClient configureStsClient() {
    LOGGER.debug("Configuring the STS client.");

    STSClient stsClient = configureBaseStsClient();

    addStsProperties(stsClient);

    setClaimsOnStsClient(stsClient, createClaimsElement());

    if (LOGGER.isDebugEnabled()) {
      logStsClientConfiguration(stsClient);
    }

    return stsClient;
  }

  /** Set the claims on the sts client. */
  private void setClaimsOnStsClient(STSClient stsClient, Element claimsElement) {
    if (claimsElement != null) {
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Setting STS claims to: {}", this.getFormattedXml(claimsElement));
      }

      stsClient.setClaims(claimsElement);
    }
  }

  /**
   * Create the claims element with the claims provided in the STS client configuration in the admin
   * console.
   */
  protected Element createClaimsElement() {
    Element claimsElement = null;
    Set<String> claims = new LinkedHashSet<>();
    claims.addAll(getClaims());

    if (contextPolicyManager != null) {
      Collection<ContextPolicy> contextPolicies = contextPolicyManager.getAllContextPolicies();
      if (contextPolicies != null && !contextPolicies.isEmpty()) {
        for (ContextPolicy contextPolicy : contextPolicies) {
          claims.addAll(contextPolicy.getAllowedAttributeNames());
        }
      }
    }

    if (!claims.isEmpty()) {
      W3CDOMStreamWriter writer = null;

      try {
        writer = new W3CDOMStreamWriter();

        writer.writeStartElement("wst", "Claims", STSUtils.WST_NS_05_12);
        writer.writeNamespace("wst", STSUtils.WST_NS_05_12);
        writer.writeNamespace("ic", "http://schemas.xmlsoap.org/ws/2005/05/identity");
        writer.writeAttribute("Dialect", "http://schemas.xmlsoap.org/ws/2005/05/identity");

        for (String claim : claims) {
          LOGGER.trace("Claim: {}", claim);
          writer.writeStartElement(
              "ic", "ClaimType", "http://schemas.xmlsoap.org/ws/2005/05/identity");
          writer.writeAttribute("Uri", claim);
          writer.writeAttribute("Optional", "true");
          writer.writeEndElement();
        }

        writer.writeEndElement();

        claimsElement = writer.getDocument().getDocumentElement();
      } catch (XMLStreamException e) {
        String msg =
            "Unable to create claims. Subjects will not have any attributes. Check STS Client configuration.";
        LOGGER.warn(msg, e);
        claimsElement = null;
      } finally {
        if (writer != null) {
          try {
            writer.close();
          } catch (XMLStreamException ignore) {
            // ignore
          }
        }
      }

      if (LOGGER.isDebugEnabled()) {
        if (claimsElement != null) {
          LOGGER.debug("Claims: {}", getFormattedXml(claimsElement));
        }
      }
    } else {
      LOGGER.debug("There are no claims to process.");
      claimsElement = null;
    }

    return claimsElement;
  }

  /** Transform into formatted XML. */
  private String getFormattedXml(Node node) {
    Document document =
        node.getOwnerDocument().getImplementation().createDocument("", "fake", null);
    Element copy = (Element) document.importNode(node, true);
    document.importNode(node, false);
    document.removeChild(document.getDocumentElement());
    document.appendChild(copy);
    DOMImplementation domImpl = document.getImplementation();
    DOMImplementationLS domImplLs = (DOMImplementationLS) domImpl.getFeature("LS", "3.0");
    if (null != domImplLs) {
      LSSerializer serializer = domImplLs.createLSSerializer();
      serializer.getDomConfig().setParameter("format-pretty-print", true);
      return serializer.writeToString(document);
    } else {
      return "";
    }
  }

  @Override
  public String getAddress() {
    return address.getResolvedString();
  }

  @Override
  public void setAddress(String address) {
    this.address = new PropertyResolver(address);
  }

  @Override
  public String getEndpointName() {
    return endpointName;
  }

  @Override
  public void setEndpointName(String endpointName) {
    this.endpointName = endpointName;
  }

  @Override
  public String getServiceName() {
    return serviceName;
  }

  @Override
  public void setServiceName(String serviceName) {
    this.serviceName = serviceName;
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public void setUsername(String username) {
    this.username = username;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public void setPassword(String password) {
    this.password = password;
  }

  @Override
  public String getSignatureUsername() {
    return signatureUsername;
  }

  @Override
  public void setSignatureUsername(String signatureUsername) {
    this.signatureUsername = signatureUsername;
  }

  @Override
  public String getSignatureProperties() {
    return signatureProperties;
  }

  @Override
  public void setSignatureProperties(String signatureProperties) {
    this.signatureProperties = signatureProperties;
  }

  @Override
  public String getEncryptionUsername() {
    return encryptionUsername;
  }

  @Override
  public void setEncryptionUsername(String encryptionUsername) {
    this.encryptionUsername = encryptionUsername;
  }

  @Override
  public String getEncryptionProperties() {
    return encryptionProperties;
  }

  @Override
  public void setEncryptionProperties(String encryptionProperties) {
    this.encryptionProperties = encryptionProperties;
  }

  @Override
  public String getTokenUsername() {
    return tokenUsername;
  }

  @Override
  public void setTokenUsername(String tokenUsername) {
    this.tokenUsername = tokenUsername;
  }

  @Override
  public String getTokenProperties() {
    return tokenProperties;
  }

  @Override
  public void setTokenProperties(String tokenProperties) {
    this.tokenProperties = tokenProperties;
  }

  @Override
  public List<String> getClaims() {
    return claims;
  }

  @Override
  public void setClaims(List<String> claims) {
    this.claims = Collections.unmodifiableList(claims);
  }

  @Override
  public void setClaims(String claimsListAsString) {

    setClaims(SPLITTER.splitToList(claimsListAsString));
  }

  @Override
  public String getAssertionType() {
    return assertionType;
  }

  @Override
  public void setAssertionType(String assertionType) {
    this.assertionType = assertionType;
  }

  @Override
  public String getKeyType() {
    return keyType;
  }

  @Override
  public void setKeyType(String keyType) {
    this.keyType = keyType;
  }

  @Override
  public String getKeySize() {
    return keySize;
  }

  @Override
  public void setKeySize(String keySize) {
    this.keySize = keySize;
  }

  @Override
  public Boolean getUseKey() {
    return useKey;
  }

  @Override
  public void setUseKey(Boolean useKey) {
    this.useKey = useKey;
  }

  /**
   * Credentials matcher class that ensures the AuthInfo received from the STS matches the AuthToken
   */
  protected static class STSCredentialsMatcher implements CredentialsMatcher {

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
      if (token instanceof SAMLAuthenticationToken) {
        Object oldToken = token.getCredentials();
        Object newToken = info.getCredentials();
        return oldToken.equals(newToken);
      } else if (token instanceof STSAuthenticationToken) {
        String xmlCreds = ((STSAuthenticationToken) token).getCredentialsAsString();
        if (xmlCreds != null && info.getCredentials() != null) {
          return xmlCreds.equals(info.getCredentials());
        }
      } else {
        if (token.getCredentials() != null && info.getCredentials() != null) {
          return token.getCredentials().equals(info.getCredentials());
        }
      }
      return false;
    }
  }
}
