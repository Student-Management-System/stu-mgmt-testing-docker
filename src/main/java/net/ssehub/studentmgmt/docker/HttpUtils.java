package net.ssehub.studentmgmt.docker;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Utility methods for HTTP requests.
 * 
 * @author Adam
 */
class HttpUtils {

    /**
     * Don't allow any instances.
     */
    private HttpUtils() {
    }
    
    /**
     * Represents the result of an HTTP response.
     */
    public static class HttpResponse {
        
        private int code;
        
        private String message;
        
        private Optional<String> body;
        
        /**
         * Retrieves the result from the given HTTP connection.
         * 
         * @param connection The connection to get the result from.
         * 
         * @throws IOException If connecting to the server fails.
         */
        private HttpResponse(HttpURLConnection connection) throws IOException {
            this.code = connection.getResponseCode();
            this.message = connection.getResponseMessage();
            if (this.message == null) {
                this.message = "";
            }
            
            try {
                readBody(connection);
            } catch (IOException e) {
                this.body = Optional.empty();
            }
        }
        
        /**
         * Reads the body content of the connection and stores it in {@link #body}.
         * 
         * @param connection The connection to read from.
         * 
         * @throws IOException If reading the body fails.
         */
        private void readBody(HttpURLConnection connection) throws IOException {
            String encoding = connection.getContentEncoding();
            Charset charset;
            if (encoding != null && Charset.isSupported(encoding)) {
                charset = Charset.forName(encoding);
            } else {
                charset = StandardCharsets.UTF_8;
            }
            
            this.body = Optional.of(new String(connection.getInputStream().readAllBytes(), charset));
        }
        
        /**
         * Whether the HTTP request was successful (HTTP status codes 200 - 299).
         * 
         * @return Whether the HTTP request was successful.
         */
        public boolean isSuccess() {
            return code >= 200 && code <= 299;
        }
        
        /**
         * Returns the status code of the HTTP request.
         * 
         * @return The status code, or -1 if an error occurred.
         */
        public int getCode() {
            return code;
        }
        
        /**
         * Returns the status message of the HTTP request.
         * 
         * @return The HTTP status message.
         */
        public String getMessage() {
            return message;
        }
        
        /**
         * Returns the body of the HTTP response.
         * 
         * @return The body or {@link Optional#empty()} if there was no body or it could not be read.
         */
        public Optional<String> getBody() {
            return body;
        }
        
        @Override
        public String toString() {
            StringBuilder result = new StringBuilder();
            result.append(code).append(' ').append(message);
            if (body.isPresent()) {
                result.append("\n\n").append(body.get());
            }
            return result.toString();
        }
        
    }
    
    /**
     * Executes a GET request on the given URL.
     * 
     * @param url The URL to request, must be a HTTP URL.
     * 
     * @return The result of the request.
     * 
     * @throws IOException If connecting to the server fails.
     */
    public static HttpResponse get(String url) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        return new HttpResponse(connection);
    }
    
    /**
     * Executes a GET request on the given URL with basic authentication.
     * 
     * @param url The URL to request, must be a HTTP URL.
     * @param username The username to authenticate as.
     * @param password The password to authenticate with.
     * 
     * @return The result of the request.
     * 
     * @throws IOException If connecting to the server fails.
     */
    public static HttpResponse getAuthenticated(String url, String username, String password) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        
        String auth = getHttpBasicAuthString(username, password);
        connection.setRequestProperty("Authorization", auth);
        
        return new HttpResponse(connection);
    }
    
    /**
     * Creates the Authorization header value for HTTP basic auth with the given username and password.
     * 
     * @param user The username to authenticate as.
     * @param password The password for the given username.
     * 
     * @return The Authorization header value.
     */
    private static String getHttpBasicAuthString(String user, String password) {
        String authString = user + ":" + password;
        String authStringEncoded = Base64.getEncoder().encodeToString(authString.getBytes(StandardCharsets.UTF_8));
        return "Basic " + authStringEncoded;
    }
    
}
