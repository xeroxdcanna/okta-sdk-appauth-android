package com.okta.auth;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationManagementRequest;
import net.openid.appauth.internal.Logger;

import org.json.JSONException;

public class OktaAuthenticationActivity extends Activity {
    static final String EXTRA_AUTH_INTENT = "com.okta.auth.AUTH_INTENT";
    //static final String EXTRA_AUTH_REQUEST = "com.okta.auth.AUTH_REQUEST";
    static final String EXTRA_AUTH_STARTED = "com.okta.auth.AUTH_STARTED";

    private boolean mAuthStarted = false;
    private Intent mAuthIntent;
    //TODO remove AuthRequest?
    private AuthorizationManagementRequest mAuthRequest;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        //In case redirect activity created a new instance of auth activity.
        if (OktaRedirectActivity.REDIRECT_ACTION.equals(getIntent().getAction())) {
            setResult(RESULT_CANCELED);
            finish();
            return;
        }

        Bundle state;
        if (savedInstanceState == null) {
            state = getIntent().getExtras();
        } else {
            state = savedInstanceState;
        }

        mAuthIntent = state.getParcelable(EXTRA_AUTH_INTENT);
        mAuthStarted = state.getBoolean(EXTRA_AUTH_STARTED, false);
        startActivity(mAuthIntent);
        mAuthStarted = true;

        /*
        try {
            String authRequestJson = state.getString(EXTRA_AUTH_REQUEST, null);
            mAuthRequest = authRequestJson != null
                    ? AuthorizationManagementRequest.jsonDeserialize(authRequestJson)
                    : null;

            startActivity(mAuthIntent);
            mAuthStarted = true;
        } catch (JSONException ex) {
            sendResult(RESULT_CANCELED, AuthorizationException.AuthorizationRequestErrors.INVALID_REQUEST.toIntent());
        }
        */
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putBoolean(EXTRA_AUTH_STARTED, mAuthStarted);
        outState.putParcelable(EXTRA_AUTH_INTENT, mAuthIntent);
        //outState.putString(EXTRA_AUTH_REQUEST, mAuthRequest.jsonSerializeString());
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (!mAuthStarted) {
            // The custom tab was closed without getting a result.
            sendResult(RESULT_CANCELED, null);
        }
        mAuthStarted = false;
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (OktaRedirectActivity.REDIRECT_ACTION.equals(intent.getAction())) {
            // We have successfully redirected back to this activity. Return the result and close.
            sendResult(RESULT_OK, intent);
        }
    }

    private void sendResult(int rc, Intent intent) {
        if (intent != null) {
            setResult(rc, intent);
        } else {
            setResult(rc);
        }
        finish();
    }
}
