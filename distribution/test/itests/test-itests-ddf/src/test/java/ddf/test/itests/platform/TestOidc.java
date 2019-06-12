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
package ddf.test.itests.platform;

import static com.jayway.restassured.RestAssured.given;
import static com.xebialabs.restito.builder.stub.StubHttp.whenHttp;
import static com.xebialabs.restito.semantics.Action.bytesContent;
import static com.xebialabs.restito.semantics.Action.contentType;
import static com.xebialabs.restito.semantics.Action.ok;
import static com.xebialabs.restito.semantics.Condition.get;
import static com.xebialabs.restito.semantics.Condition.parameter;
import static com.xebialabs.restito.semantics.Condition.post;
import static com.xebialabs.restito.semantics.Condition.withHeader;
import static org.codice.ddf.itests.common.WaitCondition.expect;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertTrue;
import static org.ops4j.pax.exam.CoreOptions.mavenBundle;
import static org.ops4j.pax.exam.CoreOptions.options;
import static org.ops4j.pax.exam.CoreOptions.wrappedBundle;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.jayway.restassured.response.Response;
import com.xebialabs.restito.semantics.Call;
import com.xebialabs.restito.server.StubServer;
import ddf.test.itests.catalog.TestFederation;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.ws.rs.core.MediaType;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.codice.ddf.itests.common.AbstractIntegrationTest;
import org.codice.ddf.test.common.DependencyVersionResolver;
import org.codice.ddf.test.common.LoggingUtils;
import org.codice.ddf.test.common.annotations.AfterExam;
import org.codice.ddf.test.common.annotations.BeforeExam;
import org.json.simple.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.junit.PaxExam;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerSuite;
import org.osgi.service.cm.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RunWith(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class TestOidc extends AbstractIntegrationTest {

  private static final Logger LOGGER = LoggerFactory.getLogger(TestFederation.class);

  private static final String OIDC_AUTH_TYPES = "/=OIDC,/solr=SAML|PKI|basic";

  private static final DynamicUrl SEARCH_URL =
      new DynamicUrl(DynamicUrl.SECURE_ROOT, HTTPS_PORT, "/search/catalog");

  private static final DynamicUrl LOGOUT_REQUEST_URL =
      new DynamicUrl(SERVICE_ROOT, "/logout/actions");

  public static final String BROWSER_USER_AGENT =
      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36";

  private static final DynamicPort IDP_PORT =
      new DynamicPort("org.codice.ddf.system_metadata_stub_server_port", 9);

  private static final String METADATA_PATH =
      "/auth/realms/master/.well-known/openid-configuration";

  private static final String TOKEN_ENDPOINT_PATH =
      "/auth/realms/master/protocol/openid-connect/token";

  private static final DynamicUrl URL_START = new DynamicUrl(DynamicUrl.INSECURE_ROOT, IDP_PORT);

  private static final String CODE =
      "6c8cc55f-5942-463d-b41e-48095dc99aa7.170c2093-3dce-4553-9ad4-fc2dadb0997d.970cf267-fe8f-4d27-a1ae-72f16d366a38";

  private static final String CLIENT_ID = "ddf.client";

  private static final String SECRET = "c0eb883e-8714-43aa-962f-e6b4f9486c28";

  private static StubServer server;

  @BeforeExam
  public void beforeTest() throws Exception {
    try {
      waitForSystemReady();
      getSecurityPolicy().configureWebContextPolicy(OIDC_AUTH_TYPES, null, null);
      getServiceManager().waitForAllBundles();

      // Configure OIDC Handler
      Map<String, Object> handlerConfig = new HashMap<>();
      handlerConfig.put("clientId", CLIENT_ID);
      handlerConfig.put("realm", "master");
      handlerConfig.put("secret", SECRET);
      handlerConfig.put(
          "logoutUri", URL_START.toString() + "/auth/admin/master/protocol/openid-connect/logout");
      handlerConfig.put("baseUri", URL_START.toString() + "/auth");
      handlerConfig.put("discoveryUri", URL_START.toString() + METADATA_PATH);
      handlerConfig.put("scope", "openid profile email resource.read");
      handlerConfig.put("useNonce", true);
      handlerConfig.put("responseMode", "form_post");
      setConfig(handlerConfig);

      server = new StubServer(Integer.parseInt(IDP_PORT.getPort())).run();
      server.start();

      // host metadata
      whenHttp(server)
          .match(get(METADATA_PATH))
          .then(
              ok(),
              contentType(MediaType.APPLICATION_JSON),
              bytesContent(
                  getFileContent("oidcMetadata.json")
                      .replaceAll("\\{\\{IDP_PORT}}", IDP_PORT.getPort())
                      .getBytes()));

    } catch (Exception e) {
      LoggingUtils.failWithThrowableStacktrace(e, "Failed in @BeforeExam: ");
    }
  }

  @AfterExam
  public void afterExam() throws Exception {
    clearCatalog();
    getSecurityPolicy().configureRestForGuest();

    if (server != null) {
      server.stop();
    }
  }

  @Test
  public void testImplicitFlowLogin() throws Exception {
    // Configure DDF to use implicit flow
    setConfig(ImmutableMap.of("responseType", "id_token"));

    // Send initial request to search
    // @formatter:off
    Response initialResponse =
        given()
            .header("User-Agent", BROWSER_USER_AGENT)
            .redirects()
            .follow(false)
            .expect()
            .statusCode(302)
            .when()
            .get(SEARCH_URL.getUrl());
    // @formatter:on

    // Assert the request that would be sent to keycloak
    String location = initialResponse.header("Location");
    assertThat(location, is(notNullValue()));

    URI locationUri = new URI(location);
    assertThat(locationUri.getPath(), is("/auth/realms/master/protocol/openid-connect/auth"));
    Map<String, String> requestParams =
        URLEncodedUtils.parse(locationUri, StandardCharsets.UTF_8)
            .stream()
            .collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));

    assertTrue(requestParams.containsKey("scope"));
    assertTrue(requestParams.containsKey("response_type"));
    assertTrue(requestParams.containsKey("client_id"));
    assertTrue(requestParams.containsKey("response_mode"));
    assertTrue(requestParams.containsKey("redirect_uri"));
    assertTrue(requestParams.containsKey("state"));
    assertTrue(requestParams.containsKey("nonce"));

    assertThat(requestParams.get("scope"), is("openid profile email resource.read"));
    assertThat(requestParams.get("response_type"), is("id_token"));
    assertThat(requestParams.get("client_id"), is(CLIENT_ID));
    assertThat(requestParams.get("response_mode"), is("form_post"));

    // Respond to request after user logged in
    Response searchResponse =
        given()
            .cookies(initialResponse.cookies())
            .header("User-Agent", BROWSER_USER_AGENT)
            .header("Host", "localhost:" + HTTPS_PORT.getPort())
            .header("Origin", URL_START.toString())
            .param("state", requestParams.get("state"))
            .param("id_token", createIdToken())
            .redirects()
            .follow(false)
            .expect()
            .statusCode(302)
            .when()
            .post(requestParams.get("redirect_uri"));

    String redirectUrl = searchResponse.header("Location");
    assertThat(redirectUrl, is(SEARCH_URL.getUrl()));
  }

  @Test
  public void testCodeFlowLogin() throws Exception {
    // Configure DDF to use authorization flow
    setConfig(ImmutableMap.of("responseType", "code"));

    // Send initial request to search
    // @formatter:off
    Response initialResponse =
        given()
            .header("User-Agent", BROWSER_USER_AGENT)
            .redirects()
            .follow(false)
            .expect()
            .statusCode(302)
            .when()
            .get(SEARCH_URL.getUrl());
    // @formatter:on

    // Assert the request that would be sent to keycloak
    String location = initialResponse.header("Location");
    assertThat(location, is(notNullValue()));

    URI locationUri = new URI(location);
    assertThat(locationUri.getPath(), is("/auth/realms/master/protocol/openid-connect/auth"));

    Map<String, String> requestParams =
        URLEncodedUtils.parse(locationUri, StandardCharsets.UTF_8)
            .stream()
            .collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));

    assertTrue(requestParams.containsKey("scope"));
    assertTrue(requestParams.containsKey("response_type"));
    assertTrue(requestParams.containsKey("client_id"));
    assertTrue(requestParams.containsKey("response_mode"));
    assertTrue(requestParams.containsKey("redirect_uri"));
    assertTrue(requestParams.containsKey("state"));
    assertTrue(requestParams.containsKey("nonce"));

    assertThat(requestParams.get("scope"), is("openid profile email resource.read"));
    assertThat(requestParams.get("response_type"), is("code"));
    assertThat(requestParams.get("client_id"), is(CLIENT_ID));
    assertThat(requestParams.get("response_mode"), is("form_post"));

    // Add token endpoint information to stub server
    String basicAuthHeader =
        "Basic "
            + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":" + SECRET).getBytes(StandardCharsets.UTF_8));
    whenHttp(server)
        .match(
            post(TOKEN_ENDPOINT_PATH),
            parameter("code", CODE),
            parameter("grant_type", "authorization_code"),
            withHeader("Authorization", basicAuthHeader))
        .then(
            ok(),
            contentType("application/json"),
            bytesContent(createValidTokenEndpointResponse().getBytes()));

    // Respond to request after user logged in
    Response searchResponse =
        given()
            .cookies(initialResponse.cookies())
            .header("User-Agent", BROWSER_USER_AGENT)
            .header("Host", "localhost:" + HTTPS_PORT.getPort())
            .header("Origin", URL_START.toString())
            .param("code", CODE)
            .param("state", requestParams.get("state"))
            .redirects()
            .follow(false)
            .expect()
            .statusCode(302)
            .when()
            .post(requestParams.get("redirect_uri"));

    String redirectUrl = searchResponse.header("Location");
    assertThat(redirectUrl, is(SEARCH_URL.getUrl()));

    // verify that the stub server was hit
    List<Call> tokenEndpointCalls =
        server
            .getCalls()
            .stream()
            .filter(call -> call.getMethod().getMethodString().equals("POST"))
            .filter(call -> call.getUrl().equals(URL_START + TOKEN_ENDPOINT_PATH))
            .collect(Collectors.toList());
    assertThat(tokenEndpointCalls.size(), is(1));
  }

  /**
   * @return a JSON response that the token endpoint would respond to containing all three tokens
   *     and extra information.
   */
  private String createValidTokenEndpointResponse() {
    JSONObject jsonObject = new JSONObject();
    jsonObject.put("access_token", createAccessToken());
    jsonObject.put("expires_in", 60);
    jsonObject.put("refresh_expires_in", 1800);
    jsonObject.put("refresh_token", createRefreshToken());
    jsonObject.put("token_type", "bearer");
    jsonObject.put("id_token", createIdToken());
    jsonObject.put("not-before-policy", 0);
    jsonObject.put("session_state", "51548995-5caa-4636-9ef6-eaba037d9625");
    jsonObject.put("scope", "openid profile email");
    return jsonObject.toJSONString();
  }

  /** @return an ID token to respond to DDF */
  private String createIdToken() {
    Algorithm algorithm = Algorithm.HMAC256("secret");
    String[] roles = {"create-realm", "offline_access", "admin", "uma_authorization"};
    long exp = Instant.now().plus(Duration.ofDays(3)).toEpochMilli();

    return JWT.create()
        .withJWTId("a410a078-8cf4-4cd5-8a7b-4eb4d8e67635")
        .withExpiresAt(new Date(exp))
        .withClaim("nbf", 0)
        .withIssuedAt(new Date())
        .withIssuer(URL_START.toString() + "/auth/realms/master")
        .withAudience(CLIENT_ID)
        .withSubject("fa0e76c5-5a58-483a-bb8c-8a3cf72cdde5")
        .withClaim("typ", "ID")
        .withClaim("azp", CLIENT_ID)
        .withClaim("auth_time", 1560279088)
        .withArrayClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role", roles)
        .withClaim("email_verified", false)
        .withClaim("preferred_username", "admin")
        .sign(algorithm);
  }

  /** @return an access token to respond to DDF */
  private String createAccessToken() {
    Algorithm algorithm = Algorithm.HMAC256("secret");
    long exp = Instant.now().plus(Duration.ofDays(3)).toEpochMilli();

    String[] audience = {"master-realm", "account"};
    String[] allowed = {"https://localhost:" + HTTPS_PORT.getPort()};
    String[] roles = {"create-realm", "offline_access", "admin", "uma_authorization"};

    JSONObject realmAccess = new JSONObject();
    realmAccess.put(
        "roles", ImmutableList.of("create-realm", "offline_access", "admin", "uma_authorization"));

    JSONObject resourceAccess = createMasterRealmJsonObject();

    return JWT.create()
        .withJWTId("cd81e810-0a49-4c01-8e00-d020d7cd3adb")
        .withExpiresAt(new Date(exp))
        .withClaim("nbf", 0)
        .withIssuedAt(new Date())
        .withIssuer(URL_START.toString() + "/auth/realms/master")
        .withArrayClaim("aud", audience)
        .withSubject("fa0e76c5-5a58-483a-bb8c-8a3cf72cdde5")
        .withClaim("typ", "Bearer")
        .withClaim("azp", CLIENT_ID)
        .withClaim("auth_time", 1560279088)
        .withArrayClaim("allowed-origins", allowed)
        .withClaim("realm_access", realmAccess.toString())
        .withClaim("resource_access", resourceAccess.toString())
        .withClaim("scope", "openid profile email")
        .withArrayClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role", roles)
        .withClaim("email_verified", false)
        .withClaim("preferred_username", "admin")
        .sign(algorithm);
  }

  /** @return a refresh token to respond to DDF */
  private String createRefreshToken() {
    Algorithm algorithm = Algorithm.HMAC256("secret");
    long exp = Instant.now().plus(Duration.ofDays(3)).toEpochMilli();
    String[] audience = {"master-realm", "account"};

    JSONObject realmAccess = new JSONObject();
    realmAccess.put(
        "roles", ImmutableList.of("create-realm", "offline_access", "admin", "uma_authorization"));

    JSONObject resourceAccess = createMasterRealmJsonObject();

    return JWT.create()
        .withJWTId("dad9d2d2-642a-4c8c-80b8-b9ec3302a59e")
        .withExpiresAt(new Date(exp))
        .withClaim("nbf", 0)
        .withIssuedAt(new Date())
        .withIssuer(URL_START.toString() + "/auth/realms/master")
        .withAudience(URL_START.toString() + "/auth/realms/master")
        .withArrayClaim("aud", audience)
        .withSubject("fa0e76c5-5a58-483a-bb8c-8a3cf72cdde5")
        .withClaim("typ", "Refresh")
        .withClaim("azp", CLIENT_ID)
        .withClaim("auth_time", 0)
        .withClaim("realm_access", realmAccess.toString())
        .withClaim("resource_access", resourceAccess.toString())
        .withClaim("scope", "openid profile email")
        .sign(algorithm);
  }

  /** Used in the creation of access tokens and refresh tokens */
  private JSONObject createMasterRealmJsonObject() {
    JSONObject masterRealm = new JSONObject();
    masterRealm.put(
        "roles",
        ImmutableList.of(
            "view-realm",
            "view-identity-providers",
            "manage-identity-providers",
            "impersonation",
            "create-client",
            "manage-users",
            "query-realms",
            "view-authorization",
            "query-clients",
            "query-users",
            "manage-events",
            "manage-realm",
            "view-events",
            "view-users",
            "view-clients",
            "manage-authorization",
            "manage-clients",
            "query-groups"));

    JSONObject account = new JSONObject();
    account.put(
        "roles", ImmutableList.of("manage-account", "manage-account-links", "view-profile"));

    JSONObject resourceAccess = new JSONObject();
    resourceAccess.put("master-realm", masterRealm);
    resourceAccess.put("account", account);
    return resourceAccess;
  }

  private void setConfig(Map<String, Object> params) throws IOException {
    // Update the config
    Configuration config =
        getAdminConfig()
            .getConfiguration("org.codice.ddf.security.oidc.client.HandlerConfiguration", null);

    for (Map.Entry<String, Object> entry : params.entrySet()) {
      // @formatter:off
      config.update(
          new Hashtable<String, Object>() {
            {
              put(entry.getKey(), entry.getValue());
            }
          });
      // @formatter:on

      // We have to make sure the config has been updated before we can use it
      // @formatter:off
      expect("Configs to update")
          .within(2, TimeUnit.MINUTES)
          .until(
              () ->
                  config.getProperties() != null
                      && (config.getProperties().get(entry.getKey()) != null));
      // @formatter:on
    }
  }

  /** Adds library use to create JWT tokens when responding to DDF */
  @Override
  protected Option[] configureCustom() {
    Option[] addedOption =
        options(
            wrappedBundle(
                mavenBundle("com.auth0", "java-jwt")
                    .version(DependencyVersionResolver.resolver())));
    return combineOptions(super.configureCustom(), addedOption);
  }
}
