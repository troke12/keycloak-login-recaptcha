package org.keycloak.marjaa.providers.login.recaptcha.authenticator;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;
import org.keycloak.marjaa.providers.login.recaptcha.resource.RecaptchaResourceProviderFactory;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.Errors;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.io.InputStream;
import java.net.URI;
import java.util.*;

public class RecaptchaUsernamePasswordForm extends UsernamePasswordForm implements Authenticator{
	public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
	public static final String SITE_KEY = "site.key";
	public static final String SITE_SECRET = "secret";
	public static final String USE_RECAPTCHA_NET = "useRecaptchaNet";
	public static final String CONFIG_VERSION = "recaptcha.version";
	public static final String VERSION_V2 = "v2";
	public static final String VERSION_V3 = "v3";
	public static final String CONFIG_MIN_SCORE = "min.score";
	public static final String DEFAULT_MIN_SCORE = "0.5";
	private static final Logger logger = Logger.getLogger(RecaptchaUsernamePasswordForm.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
		if (logger.isInfoEnabled()) {
			logger.info(
					"validateRecaptcha(AuthenticationFlowContext, boolean, String, String) - Before the validation");
		}

		AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
		LoginFormsProvider form = context.form();

		if (captchaConfig == null || captchaConfig.getConfig() == null
		        || captchaConfig.getConfig().get(SITE_KEY) == null
		        || captchaConfig.getConfig().get(SITE_SECRET) == null) {
		    form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
		    super.authenticate(context);
		    return;
		}

//		if (captchaConfig == null || captchaConfig.getConfig() == null
//				|| captchaConfig.getConfig().get(SITE_KEY) == null
//				|| captchaConfig.getConfig().get(SITE_SECRET) == null) {
//			form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
//			return;
//		}

		String siteKey = captchaConfig.getConfig().get(SITE_KEY);

		// Load the widget via our own resource-provider endpoint (self-injecting JS) instead of
		// theme attributes/markup, so this works against any login theme without touching it.
		URI baseUri = context.getSession().getContext().getUri().getBaseUri();
		String injectUrl = UriBuilder.fromUri(baseUri)
				.path("realms")
				.path(context.getRealm().getName())
				.path(RecaptchaResourceProviderFactory.ID)
				.path("inject.js")
				.queryParam("siteKey", siteKey)
				.queryParam("domain", getRecaptchaDomain(captchaConfig))
				.queryParam("version", getVersion(captchaConfig))
				.build()
				.toString();
		form.addScript(injectUrl);

		super.authenticate(context);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		if (logger.isDebugEnabled()) {
			logger.debug("action(AuthenticationFlowContext) - start");
		}
		MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
		List<FormMessage> errors = new ArrayList<>();
		boolean success = false;
		context.getEvent().detail(Details.AUTH_METHOD, "auth_method");

		String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
		if (!Validation.isBlank(captcha)) {
			AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
			String secret = captchaConfig.getConfig().get(SITE_SECRET);

			success = validateRecaptcha(context, success, captcha, secret);
		}
		if (success) {
			super.action(context);
		} else {
    			formData.remove(G_RECAPTCHA_RESPONSE);
    			context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
   			context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
            			challenge(context, Messages.RECAPTCHA_FAILED));
    			return;
		}
//		} else {
//			errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
//			formData.remove(G_RECAPTCHA_RESPONSE);
//			context.error(Errors.INVALID_REGISTRATION);
//			context.validationError(formData, errors);
//			context.excludeOtherErrors();
//			return;
//		}

		if (logger.isDebugEnabled()) {
			logger.debug("action(AuthenticationFlowContext) - end");
		}
	}

	private String getRecaptchaDomain(AuthenticatorConfigModel config) {
		Boolean useRecaptcha = Optional.ofNullable(config)
				.map(configModel -> configModel.getConfig())
				.map(cfg -> Boolean.valueOf(cfg.get(USE_RECAPTCHA_NET)))
				.orElse(false);
		if (useRecaptcha) {
			return "recaptcha.net";
		}

		return "google.com";
	}

	private String getVersion(AuthenticatorConfigModel config) {
		String version = Optional.ofNullable(config)
				.map(configModel -> configModel.getConfig())
				.map(cfg -> cfg.get(CONFIG_VERSION))
				.orElse(VERSION_V2);
		return VERSION_V3.equals(version) ? VERSION_V3 : VERSION_V2;
	}

	private double getMinScore(AuthenticatorConfigModel config) {
		String raw = Optional.ofNullable(config)
				.map(configModel -> configModel.getConfig())
				.map(cfg -> cfg.get(CONFIG_MIN_SCORE))
				.orElse(DEFAULT_MIN_SCORE);
		try {
			return Double.parseDouble(raw);
		} catch (NumberFormatException | NullPointerException e) {
			return Double.parseDouble(DEFAULT_MIN_SCORE);
		}
	}

	protected boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha, String secret) {
		HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
		HttpPost post = new HttpPost("https://www." + getRecaptchaDomain(context.getAuthenticatorConfig()) + "/recaptcha/api/siteverify");
		List<NameValuePair> formparams = new LinkedList<>();
		formparams.add(new BasicNameValuePair("secret", secret));
		formparams.add(new BasicNameValuePair("response", captcha));
		formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
		try {
			UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
			post.setEntity(form);
			HttpResponse response = httpClient.execute(post);
			InputStream content = response.getEntity().getContent();
			try {
				Map json = JsonSerialization.readValue(content, Map.class);
				success = Boolean.TRUE.equals(json.get("success"));

				AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
				if (success && VERSION_V3.equals(getVersion(captchaConfig))) {
					Object scoreObj = json.get("score");
					double score = scoreObj instanceof Number ? ((Number) scoreObj).doubleValue() : 0.0;
					success = score >= getMinScore(captchaConfig);
				}
			} finally {
				content.close();
			}
		} catch (Exception e) {
			ServicesLogger.LOGGER.recaptchaFailed(e);
		}
		return success;
	}

}
