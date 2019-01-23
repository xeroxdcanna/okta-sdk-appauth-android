package com.okta.auth;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.support.annotation.ColorInt;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.WorkerThread;
import android.support.customtabs.CustomTabsIntent;
import android.text.TextUtils;
import android.util.Log;

import com.okta.appauth.android.AuthenticationPayload;

import net.openid.appauth.AppAuthConfiguration;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationManagementResponse;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.AuthorizationServiceDiscovery;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.connectivity.DefaultConnectionBuilder;
import net.openid.appauth.internal.Logger;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static android.app.Activity.RESULT_CANCELED;
import static com.okta.auth.OktaAuthenticationActivity.EXTRA_AUTH_INTENT;

public class OktaAuth {
    private static final String TAG = OktaAuth.class.getSimpleName();

    //Persist options default is shared pref.
    public enum Persist {
        DEFAULT, SECURE, CUSTOM;
    }

    private Activity mActivity;
    private OktaAuthProvider mOktaAuthProvider;
    private AuthCallback mCallback;
    private Persist mPersistOption;
    private int mCustomTabColor;

    private AuthorizationServiceConfiguration mServiceConfig;

    private ExecutorService mExecutor;

    private AuthorizationService mService;
    private AuthorizationRequest mAuthRequest;
    private AuthorizationResponse mAuthResponse;

    private static final int REQUEST_CODE = 100;

    private OktaAuth(@NonNull Builder builder) {
        mActivity = builder.mActivity;
        mOktaAuthProvider = builder.mOktaAuthProvider;
        mCallback = builder.mCallback;
        mPersistOption = builder.mPersistOption;
        mCustomTabColor = builder.mCustomTabColor;
        mExecutor = Executors.newSingleThreadExecutor();
    }

    public void startAuthorize() {
        if (mServiceConfig == null) {
            mExecutor.submit(() -> {
                mServiceConfig = fetchServiceConfiguration();
            });
        }
        mExecutor.submit(this::authenticate);
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQUEST_CODE) {
            return;
        }
        if (resultCode == RESULT_CANCELED) {
            mCallback.onCancel();
            return;
        }
        Uri responseUri = data.getData();
        Intent responseData = extractResponseData(responseUri);
        if (responseData == null) {
            Logger.error("Failed to extract OAuth2 response from redirect");
            mCallback.onError("Failed to extract OAuth2 response from redirect", null);
            return;
        }
        //TODO handle other response types.
        AuthorizationManagementResponse response =
                AuthorizationManagementResponse.fromIntent(responseData);
        AuthorizationException ex = AuthorizationException.fromIntent(responseData);

        if (ex != null || response == null) {
            Log.w(TAG, "Authorization flow failed: " + ex);
            mCallback.onCancel();
        } else if (response instanceof AuthorizationResponse) {
            mAuthResponse = (AuthorizationResponse) response;
            mCallback.onSuccess(mAuthResponse);
        } else {
            mCallback.onCancel();
        }
    }

    //TODO make class lifecycle aware
    public void onDestroy() {
        if (mService != null) {
            mService.dispose();
        }
    }

    public AuthorizationServiceConfiguration getServiceConfig() {
        return mServiceConfig;
    }

    public AuthorizationService getAuthService() {
        return mService;
    }

    private Intent extractResponseData(Uri responseUri) {
        if (responseUri.getQueryParameterNames().contains(AuthorizationException.PARAM_ERROR)) {
            return AuthorizationException.fromOAuthRedirect(responseUri).toIntent();
        } else {
            AuthorizationManagementResponse response = AuthorizationManagementResponse
                    .buildFromRequest(mAuthRequest, responseUri);

            if (mAuthRequest.getState() == null && response.getState() != null
                    || (mAuthRequest.getState() != null && !mAuthRequest.getState()
                    .equals(response.getState()))) {

                Logger.warn("State returned in authorization response (%s) does not match state "
                                + "from request (%s) - discarding response",
                        response.getState(),
                        mAuthRequest.getState());

                return AuthorizationException.AuthorizationRequestErrors.STATE_MISMATCH.toIntent();
            }

            return response.toIntent();
        }
    }

    //TODO
    @WorkerThread
    private void authenticate() {
        if (mServiceConfig != null) {
            mAuthRequest = createAuthRequest(null);
            if (mService != null) {
                mService.dispose();
            }
            AppAuthConfiguration.Builder builder = new AppAuthConfiguration.Builder();
            mService = new AuthorizationService(mActivity, builder.build());
            CustomTabsIntent.Builder intentBuilder = mService.createCustomTabsIntentBuilder(mAuthRequest.toUri());
            intentBuilder.setToolbarColor(mCustomTabColor);
            CustomTabsIntent tabsIntent = intentBuilder.build();
            tabsIntent.intent.addFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);
            Intent browserIntent = mService.prepareAuthorizationRequestIntent(mAuthRequest, tabsIntent);
            Intent intent = new Intent(mActivity, OktaAuthenticationActivity.class);
            intent.putExtra(EXTRA_AUTH_INTENT, browserIntent);
            //intent.putExtra(EXTRA_AUTH_REQUEST, mAuthRequest.jsonSerializeString());
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
            mActivity.startActivityForResult(intent, REQUEST_CODE);
        }
    }

    //TODO
    private AuthorizationRequest createAuthRequest(@Nullable AuthenticationPayload payload) {
        AuthorizationRequest.Builder authRequestBuilder = new AuthorizationRequest.Builder(
                mServiceConfig,
                mOktaAuthProvider.getClientId(),
                ResponseTypeValues.CODE,
                mOktaAuthProvider.getRedirectUri())
                .setScopes(mOktaAuthProvider.getScopes());

        if (payload != null) {
            authRequestBuilder.setAdditionalParameters(payload.getAdditionalParameters());
            if (!TextUtils.isEmpty(payload.toString())) {
                authRequestBuilder.setState(payload.getState());
            }
            if (!TextUtils.isEmpty(payload.getLoginHint())) {
                authRequestBuilder.setLoginHint(payload.getLoginHint());
            }
        }
        return authRequestBuilder.build();
    }

    //TODO
    @WorkerThread
    private AuthorizationServiceConfiguration fetchServiceConfiguration() {
        Log.i(TAG, "Retrieving OpenID discovery doc");
        InputStream is = null;
        AuthorizationException exception = null;
        AuthorizationServiceConfiguration config = null;
        try {
            //TODO add status states to callback
            mCallback.onStatus("fetch service connection");
            HttpURLConnection conn = DefaultConnectionBuilder.INSTANCE.openConnection(mOktaAuthProvider.getDiscoveryUri());
            conn.setRequestMethod("GET");
            conn.setDoInput(true);
            conn.connect();

            is = conn.getInputStream();
            if (is == null) {
                throw new IOException("Input stream must not be null");
            }

            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            char[] buffer = new char[1024];
            StringBuilder sb = new StringBuilder();
            int readCount;
            while ((readCount = br.read(buffer)) != -1) {
                sb.append(buffer, 0, readCount);
            }
            JSONObject json = new JSONObject(sb.toString());

            AuthorizationServiceDiscovery discovery =
                    new AuthorizationServiceDiscovery(json);
            config = new AuthorizationServiceConfiguration(discovery);
        } catch (IOException ex) {
            Logger.errorWithStack(ex, "Network error when retrieving discovery document");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.NETWORK_ERROR,
                    ex);
        } catch (JSONException ex) {
            Logger.errorWithStack(ex, "Error parsing discovery document");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                    ex);
        } catch (AuthorizationServiceDiscovery.MissingArgumentException ex) {
            Logger.errorWithStack(ex, "Malformed discovery document");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.INVALID_DISCOVERY_DOCUMENT,
                    ex);
        } finally {
            try {
                if (is != null) {
                    is.close();
                }
            } catch (IOException ignored) {
                // deliberately do nothing
            }
            if (exception != null) {
                mCallback.onError("", exception);
            }
        }
        return config;
    }

    public static class Builder {
        private Activity mActivity;
        private OktaAuthProvider mOktaAuthProvider;
        private AuthCallback mCallback;
        private Persist mPersistOption = Persist.DEFAULT;
        private int mCustomTabColor;

        public Builder(@NonNull Activity activity) {
            mActivity = activity;
        }

        public OktaAuth create() {
            return new OktaAuth(this);
        }

        public Builder withCallback(@NonNull AuthCallback callback) {
            mCallback = callback;
            return this;
        }

        public Builder withProvider(@NonNull OktaAuthProvider provider) {
            mOktaAuthProvider = provider;
            return this;
        }

        public Builder withPersistOption(@NonNull Persist option) {
            mPersistOption = option;
            return this;
        }

        public Builder withTabColor(@ColorInt int customTabColor) {
            mCustomTabColor = customTabColor;
            return this;
        }
    }
}
