package io.moj.java.sdk.auth;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.net.HttpURLConnection;

/**
 * OkHttp {@link Interceptor} that adds the app's access token to request headers.
 * Created by skidson on 16-02-11.
 */
public class AuthInterceptor implements Interceptor {

    private Authenticator authenticator;
    private OnAccessTokenExpiredListener listener;

    public AuthInterceptor(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        return doIntercept(chain, true);
    }

    private Response doIntercept(Chain chain, boolean retry) throws IOException {
        Request request = chain.request();

        // set the access token in the header if we have it
        AccessToken accessToken = authenticator.getAccessToken();
        Request.Builder requestBuilder = request.newBuilder();
        if (accessToken != null) {
            requestBuilder.header("Authorization", "Bearer " + accessToken.getAccessToken());
        }
        requestBuilder.addHeader("Content-Type", "application/json");
        requestBuilder.addHeader("Accept", "application/json");
        request = requestBuilder.build();

        Response response = chain.proceed(request);
        if (response.code() == HttpURLConnection.HTTP_UNAUTHORIZED) {
            // synchronized to avoid multiple token refreshing in parallel
            synchronized (this) {
                AccessToken currentToken = authenticator.getAccessToken();

                if (currentToken != null && currentToken.equals(accessToken)) {
                    // token wasn't invalidated yet
                    authenticator.invalidateAccessToken(accessToken);
                    currentToken = authenticator.getAccessToken();
                }

                if (currentToken != null) {
                    requestBuilder.header("Authorization", "Bearer " + currentToken.getAccessToken());
                }

                request = requestBuilder.build();
                response = chain.proceed(request);
                if (response.code() == HttpURLConnection.HTTP_UNAUTHORIZED && listener != null) {
                    // got a 401 after refresh, broadcast that token no longer valid
                    listener.onAccessTokenExpired();
                }
                return response;
            }
        }
        return response;
    }

    public void setOnAccessTokenExpiredListener(OnAccessTokenExpiredListener listener) {
        this.listener = listener;
    }
}
