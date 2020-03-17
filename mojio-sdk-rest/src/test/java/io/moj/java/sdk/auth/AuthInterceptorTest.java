package io.moj.java.sdk.auth;

import io.moj.java.sdk.logging.Log;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Matchers.*;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.*;

/**
 * Created by skidson on 16-03-04.
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({Request.class, Request.Builder.class, Response.class})
public class AuthInterceptorTest {

    private static final long SECONDS_PER_MS = 1000;
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String FORMAT_BEARER = "Bearer %s";

    private AuthInterceptor interceptor;
    private Log.Logger logger;
    private Authenticator authenticator;
    private OnAccessTokenExpiredListener listener;

    @Before
    public void setup() {
        logger = mock(Log.Logger.class);
        authenticator = mock(Authenticator.class);
        listener = mock(OnAccessTokenExpiredListener.class);

        interceptor = new AuthInterceptor(authenticator);
        interceptor.setOnAccessTokenExpiredListener(listener);

        Log.clearLoggers();
        Log.append(logger);
    }

    @Test
    public void testIntercept_noAccount_ok() throws IOException {
        int expectedCode = 200;
        Mock mock = mockChain(expectedCode, 0);

        Response actualResponse = interceptor.intercept(mock.chain);
        assertThat(actualResponse).isEqualTo(mock.response);

        // verify we did not trigger the OnAccessTokenExpiredListener
        verify(listener, never()).onAccessTokenExpired();
    }

    @Test
    public void testIntercept_validAccount() throws IOException {
        int expectedCode = 200;
        String expectedAuthToken = "expectedAuthToken";
        long expectedExpiresTimestamp = System.currentTimeMillis() + (SECONDS_PER_MS * 120);

        mockAuthToken(expectedAuthToken, null, expectedExpiresTimestamp);
        Mock mock = mockChain(expectedCode, 0);

        Response actualResponse = interceptor.intercept(mock.chain);
        assertThat(actualResponse).isEqualTo(mock.response);

        // verify we attached the auth token to the Authorization header
        String expectedAuthHeader = String.format(Locale.US, FORMAT_BEARER, expectedAuthToken);
        verify(mock.request.newBuilder()).header(HEADER_AUTHORIZATION, expectedAuthHeader);

        // verify we did not trigger the OnAccessTokenExpiredListener
        verify(listener, never()).onAccessTokenExpired();
    }

    @Test
    public void testIntercept_expiredAccount() throws IOException {
        int expectedCode = HttpURLConnection.HTTP_UNAUTHORIZED;
        String expectedAuthToken = "expectedAuthToken";
        long expectedExpiresTimestamp = System.currentTimeMillis() - 1000;

        AccessToken token = mockAuthToken(expectedAuthToken, null, expectedExpiresTimestamp);
        Mock mock = mockChain(expectedCode, 0);

        Response actualResponse = interceptor.intercept(mock.chain);
        assertThat(actualResponse).isEqualTo(mock.response);

        verify(authenticator).invalidateAccessToken(token);
        verify(listener).onAccessTokenExpired();
    }

    @Test
    public void testIntercept_refreshConcurrent() throws Exception {
        int parallelRequests = 5;

        int expectedCode = HttpURLConnection.HTTP_UNAUTHORIZED;
        String expiredAuthToken = "expectedAuthToken";
        long expiredTokenExpiresTimestamp = System.currentTimeMillis() - 1000;
        final AccessToken expiredAccessToken = mockAuthToken(expiredAuthToken, null, expiredTokenExpiresTimestamp);

        String refreshedAuthToken = "refreshedAuthToken";
        long refreshedTokenExpiresTimestamp = System.currentTimeMillis() + 1000;
        final AccessToken refreshedAccessToken = mockAuthToken(refreshedAuthToken, null, refreshedTokenExpiresTimestamp);

        final Mock mock = mockChain(expectedCode, 2000L);

        final AtomicInteger invalidationCounter = new AtomicInteger(0);
        when(authenticator.getAccessToken()).then(new Answer<AccessToken>() {
            @Override
            public AccessToken answer(InvocationOnMock invocation) {
                if (invalidationCounter.get() > 0) {
                    return refreshedAccessToken;
                } else {
                    return expiredAccessToken;
                }
            }
        });
        doAnswer(new Answer<Void>() {
            @Override
            public Void answer(InvocationOnMock invocation) {
                invalidationCounter.incrementAndGet();
                return null;
            }
        }).when(authenticator).invalidateAccessToken(expiredAccessToken);

        final CountDownLatch countDownLatch = new CountDownLatch(parallelRequests);
        Runnable interceptRunnable = new Runnable() {
            @Override
            public void run() {
                try {
                    interceptor.intercept(mock.chain);
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    countDownLatch.countDown();
                }
            }
        };
        Executor executor = Executors.newFixedThreadPool(parallelRequests);
        for (int i = 0; i < parallelRequests; i++) {
            executor.execute(interceptRunnable);
        }

        countDownLatch.await();
        verify(authenticator, times(1)).invalidateAccessToken(any(AccessToken.class));
    }

    private static Mock mockChain(int statusCode, final long proceedDelay) throws IOException {
        Interceptor.Chain chain = mock(Interceptor.Chain.class);
        Request request = mock(Request.class);
        Request.Builder requestBuilder = mock(Request.Builder.class);
        final Response response = mock(Response.class);
        when(chain.request()).thenReturn(request);
        when(request.newBuilder()).thenReturn(requestBuilder);
        when(requestBuilder.header(anyString(), anyString())).thenReturn(requestBuilder);
        when(requestBuilder.build()).thenReturn(request);
        when(chain.proceed(request)).then(new Answer<Response>() {
            @Override
            public Response answer(InvocationOnMock invocation) throws Throwable {
                Thread.sleep(proceedDelay);
                return response;
            }
        });
        when(response.code()).thenReturn(statusCode);

        return new Mock(chain, request, response);
    }

    private AccessToken mockAuthToken(String authToken, String refreshToken, long expiresTimestamp) throws IOException {
        AccessToken token = new AccessToken(authToken, refreshToken, expiresTimestamp);
        when(authenticator.getAccessToken()).thenReturn(token);
        return token;
    }

    private static class Mock {
        private Request request;
        private Response response;
        private Interceptor.Chain chain;

        public Mock(Interceptor.Chain chain, Request request, Response response) {
            this.chain = chain;
            this.request = request;
            this.response = response;
        }
    }

}
