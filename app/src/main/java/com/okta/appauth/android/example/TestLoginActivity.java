/*
 * Copyright (c) 2017, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License,
 * Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the
 * License.
 */

package com.okta.appauth.android.example;

import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.ColorRes;
import android.support.annotation.MainThread;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.okta.appauth.android.OktaAppAuth;
import com.okta.appauth.android.OktaAppAuth.LoginHintChangeHandler;
import com.okta.auth.AuthCallback;
import com.okta.auth.OktaAuth;
import com.okta.auth.OktaAuthProvider;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceDiscovery;
import net.openid.appauth.ClientAuthentication;
import net.openid.appauth.NoClientAuthentication;
import net.openid.appauth.TokenRequest;
import net.openid.appauth.TokenResponse;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import okio.Okio;

/**
 * Example Login Activity where authentication takes place.
 */
public class TestLoginActivity extends AppCompatActivity {

    private static final String TAG = "TestLoginActivity";
    private static final String EXTRA_FAILED = "failed";

    private OktaAuth mOktAuth;
    private OktaAuthProvider mProvider;
    private OktaAuthProvider mProviderWithRes;
    private TextView mTvStatus;
    private Button mButton;
    private AuthorizationResponse mResponse;
    private TokenResponse mToken;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.test_activity_login);
        mButton = findViewById(R.id.start_button);
        mButton.setOnClickListener(v -> mOktAuth.startAuthorize());
        mTvStatus = findViewById(R.id.status);

        mProvider = new OktaAuthProvider.Builder(this)
                .clientId("0oaiv94wtjW7DHvvj0h7")
                .redirectUri("com.okta.appauth.android.example:/callback")
                .endSessionRedirectUri("com.okta.appauth.android.example:/logout")
                .scopes("openid", "profile", "offline_access")
                .discoveryUri("https://dev-486177.oktapreview.com/oauth2/default")
                .create();

        mProviderWithRes = new OktaAuthProvider.Builder(this).withResId(R.raw.okta_app_auth_config);

        mOktAuth = new OktaAuth.Builder(this).withCallback(new AuthCallback() {
            @Override
            public void onSuccess(AuthorizationResponse response) {
                mResponse = response;
                Log.d("TestLoginActivity", "SUCCESS");
                runOnUiThread(() -> {
                            mTvStatus.setText("AccessToken:" + response.jsonSerializeString());
                            mButton.setText("Exchange Auth Code");
                            mButton.setOnClickListener(v -> exchangeAuthCode());
                        }
                );
            }

            @Override
            public void onStatus(String status) {
                Log.d("TestLoginActivity", status);
                runOnUiThread(() -> mTvStatus.setText(status));
            }

            @Override
            public void onCancel() {
                Log.d("TestLoginActivity", "CANCELED!");
                runOnUiThread(() -> mTvStatus.setText("canceled"));
            }

            @Override
            public void onError(String msg, AuthorizationException error) {
                Log.d("TestLoginActivity", error.errorDescription);
            }
        }).withProvider(mProvider)
                .withTabColor(getColorCompat(R.color.colorPrimary))
                .create();

    }

    @Override
    protected void onStart() {
        super.onStart();
        if (getIntent().getBooleanExtra(EXTRA_FAILED, false)) {
            showSnackbar(getString(R.string.auth_canceled));
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        // Pass result to OktaAuth for processing
        mOktAuth.onActivityResult(requestCode, resultCode, data);
    }

    @Override
    protected void onDestroy() {
        if (mOktAuth != null) {
            mOktAuth.onDestroy();
        }
        super.onDestroy();
    }


    @MainThread
    private void showSnackbar(String message) {
        Snackbar.make(findViewById(R.id.coordinator),
                message,
                Snackbar.LENGTH_SHORT)
                .show();
    }

    private ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    private void fetchUserInfo() {
        URL userInfoEndpoint;
        try {
            userInfoEndpoint = new URL(mOktAuth.getServiceConfig().discoveryDoc.getUserinfoEndpoint().toString());
        } catch (MalformedURLException urlEx) {
            Log.e(TAG, "Failed to construct user info endpoint URL", urlEx);
            mTvStatus.setText("Failed to construct user info endpoint URL");
            return;
        }

        mExecutor.submit(() -> {
            final String response;
            try {
                HttpURLConnection conn =
                        (HttpURLConnection) userInfoEndpoint.openConnection();
                conn.setRequestProperty("Authorization", "Bearer " + mToken.accessToken);
                conn.setInstanceFollowRedirects(false);
                response = Okio.buffer(Okio.source(conn.getInputStream()))
                        .readString(Charset.forName("UTF-8"));
                runOnUiThread(() -> mButton.setText(response));
            } catch (IOException ioEx) {
                Log.e(TAG, "Network error when querying userinfo endpoint", ioEx);
                showSnackbar("Fetching user info failed");
            }
        });
    }


    private void exchangeAuthCode() {
        if (mResponse != null && mResponse.authorizationCode != null) {

            mOktAuth.getAuthService().performTokenRequest(
                    mResponse.createTokenExchangeRequest(),
                    NoClientAuthentication.INSTANCE,
                    new AuthorizationService.TokenResponseCallback() {
                        @Override
                        public void onTokenRequestCompleted(@Nullable TokenResponse response,
                                                            @Nullable AuthorizationException ex) {
                            if (response != null) {
                                mToken = response;
                                mTvStatus.setText("Token Exchange Success");
                                mButton.setText("FetchUserInfo");
                                mButton.setOnClickListener(v -> fetchUserInfo());
                            } else {
                                mTvStatus.setText("Token exchange error");
                                Log.d(TAG, "", ex);
                            }

                        }
                    });
        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    @SuppressWarnings("deprecation")
    private int getColorCompat(@ColorRes int color) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return getColor(color);
        } else {
            return getResources().getColor(color);
        }
    }
}
