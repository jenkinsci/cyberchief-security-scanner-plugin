package io.jenkins.plugins.cyberchief;

import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.model.Action;
import hudson.model.TaskListener;
import hudson.util.Secret;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;

public class CyberChiefScanAction implements Action {

    private Secret token;
    private String scope;
    private String apiResponse;

    private String buildQueryString(Map<String, String> parameters) throws UnsupportedEncodingException {
        StringBuilder query = new StringBuilder();
        boolean first = true;

        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            if (first) {
                first = false;
            } else {
                query.append("&");
            }

            query.append(URLEncoder.encode(entry.getKey(), "UTF-8"))
                    .append("=")
                    .append(URLEncoder.encode(entry.getValue(), "UTF-8"));
        }

        return "?" + query.toString();
    }

    private void printVulnerabilitiesDetails(JSONArray vulnerabilities, TaskListener listener) {
        for (int i = 0; i < vulnerabilities.length(); i++) {
            try {
                JSONObject vulnerability = vulnerabilities.getJSONObject(i);

                // Extract other details, adjust as needed
                String id = vulnerability.optString("id", "");
                String title = vulnerability.optString("title", "");
                String risk = vulnerability.optString("risk", "");
                String originalLink = vulnerability.optString("link", "");

                listener.getLogger().println("ID: " + id);
                listener.getLogger().println("Title: " + title);
                listener.getLogger().println("Risk: " + risk);
                listener.getLogger().println("Original Link: " + originalLink);
            } catch (JSONException e) {
                e.printStackTrace();
                throw new RuntimeException("Error parsing JSON response: " + e.getMessage());
            }
        }
    }

    public CyberChiefScanAction(Secret token, String scope) {
        this.token = token;
        this.scope = scope;
    }

    public Secret getToken() {
        return token;
    }

    public String getScope() {
        return scope;
    }

    public String getApiResponse() {
        return apiResponse;
    }

    @Override
    public String getIconFileName() {
        // You can return the path to an icon file (e.g., "/plugin/my-plugin/images/icon.png")
        // or return null if you don't want an icon
        return null;
    }

    @Override
    public String getDisplayName() {
        return "Cyber Chief Security Scanner";
    }

    @Override
    public String getUrlName() {
        return "cyberchief";
    }

    // Web App Scan
    public void makeWebAppScanRequest(String apiUrl, Secret authToken, String scope, TaskListener listener) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            // Set request method and headers
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", "Token " + authToken);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            // Enable output and write form data to the request body
            connection.setDoOutput(true);
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = ("test_scope=" + scope + "&is_jenkins_scan=" + "True").getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
            // Get the response
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder response = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                response.append(line);
            }

            reader.close();

            System.out.println("API Response: " + response.toString());
            JSONObject jsonResponse = new JSONObject(response.toString());
            String message = jsonResponse.optString("message", "").toLowerCase();
            String statusUrl = jsonResponse.optString("status_url", "").toLowerCase();
            listener.getLogger().println("Response: " + message);
            listener.getLogger().println("Status URL: " + statusUrl);

            apiResponse = response.toString();
            connection.disconnect();
        } catch (RuntimeException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Polling interrupted.");

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("An error occurred: " + e.getMessage());
        }
    }

    // API Scan
    public void makeApiScanRequest(String apiUrl, Secret authToken, String apiName, TaskListener listener) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            // Set request method and headers
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", "Token " + authToken);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            // Enable output and write form data to the request body
            connection.setDoOutput(true);
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = ("api_name=" + apiName + "&is_jenkins_scan=" + "True").getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }
            // Get the response
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder response = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                response.append(line);
            }

            reader.close();

            System.out.println("API Response: " + response.toString());
            JSONObject jsonResponse = new JSONObject(response.toString());
            String message = jsonResponse.optString("message", "").toLowerCase();
            String statusUrl = jsonResponse.optString("status_url", "").toLowerCase();
            listener.getLogger().println("Response: " + message);
            listener.getLogger().println("Status URL: " + statusUrl);

            apiResponse = response.toString();
            connection.disconnect();
        } catch (RuntimeException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Polling interrupted.");

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("An error occurred: " + e.getMessage());
        }
    }

    // Raider Scan
    public void makeRaiderScanRequest(
            String apiUrl,
            Secret authToken,
            String raiderName,
            String[] regionsList,
            String[] frameworksList,
            String[] servicesList,
            TaskListener listener) {
        try {
            URL url = new URL(apiUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            // Set request method and headers
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", "Token " + authToken);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            // Enable output and write form data to the request body
            connection.setDoOutput(true);
            try (OutputStream os = connection.getOutputStream()) {
                ObjectMapper objectMapper = new ObjectMapper();

                // Convert regionsList to a JSON array
                String regionsJson = objectMapper.writeValueAsString(regionsList);
                String servicesJson = objectMapper.writeValueAsString(servicesList);
                String farmeworksJson = objectMapper.writeValueAsString(frameworksList);

                byte[] input = ("raider_name=" + raiderName + "&regions=" + regionsJson + "&frameworks="
                                + farmeworksJson + "&services=" + servicesJson + "&is_jenkins_scan=" + "True")
                        .getBytes(StandardCharsets.UTF_8);

                os.write(input, 0, input.length);
            }
            // Get the response
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));
            StringBuilder response = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                response.append(line);
            }

            reader.close();

            System.out.println("API Response: " + response.toString());
            JSONObject jsonResponse = new JSONObject(response.toString());
            String message = jsonResponse.optString("message", "").toLowerCase();
            String statusUrl = jsonResponse.optString("status_url", "").toLowerCase();
            listener.getLogger().println("Response: " + message);
            listener.getLogger().println("Status URL: " + statusUrl);

            apiResponse = response.toString();
            connection.disconnect();
        } catch (RuntimeException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Polling interrupted.");

        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("An error occurred: " + e.getMessage());
        }
    }

    public String extractStatusUrl() {
        try {
            JSONObject jsonResponse = new JSONObject(apiResponse);
            return jsonResponse.optString("status_url", null);
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void pollStatusUrl(
            String statusUrl,
            Secret authToken,
            boolean requestComplete,
            boolean failOnHighVulns,
            boolean failOnHighMediumVulns,
            TaskListener listener) {
        while (!requestComplete) {
            try {

                Map<String, String> parameters = Map.of(
                        "failonHighVulns", StringUtils.capitalize(String.valueOf(failOnHighVulns)),
                        "failOnHighMediumVulns", StringUtils.capitalize(String.valueOf(failOnHighMediumVulns)));

                URL url = new URL(statusUrl + buildQueryString(parameters));
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                connection.setRequestProperty("Authorization", "Token " + authToken);
                connection.setRequestProperty("Retry-After", "60");

                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder response = new StringBuilder();
                    String line;

                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }

                    // Check the response for completion status
                    requestComplete =
                            isScanTaskComplete(response.toString(), failOnHighVulns, failOnHighMediumVulns, listener);
                }

                Thread.sleep(1000);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new RuntimeException("Polling interrupted.");

            } catch (Exception e) {
                e.printStackTrace();
                throw new RuntimeException("An error occurred: " + e.getMessage());
            }
        }
    }

    private boolean isScanTaskComplete(
            String statusResponse, boolean failOnHighVulns, boolean failOnHighMediumVulns, TaskListener listener) {
        try {
            StringBuilder message = new StringBuilder();
            JSONObject jsonResponse = new JSONObject(statusResponse);
            String status = jsonResponse.optString("status", "").toLowerCase();

            if ("failed".equals(status) || "completed".equals(status)) {
                JSONObject vulnerabilityDetails = jsonResponse.optJSONObject("vulnerabilities");

                if (vulnerabilityDetails != null) {
                    JSONArray highVulnerabilities = vulnerabilityDetails.optJSONArray("high");
                    JSONArray mediumVulnerabilities = vulnerabilityDetails.optJSONArray("medium");

                    if (highVulnerabilities != null) {
                        if (highVulnerabilities.length() > 0) {
                            listener.getLogger().println("============= High Vulnerabilities ==================");
                            printVulnerabilitiesDetails(highVulnerabilities, listener);
                        }
                        message.append("Number of High Vulnerabilities Found: " + highVulnerabilities.length());
                    }

                    if (mediumVulnerabilities != null) {
                        if (mediumVulnerabilities.length() > 0) {
                            listener.getLogger().println("============= Medium Vulnerabilities ===============");
                            printVulnerabilitiesDetails(mediumVulnerabilities, listener);
                        }
                        message.append(", Number of Medium Vulnerabilities Found: " + mediumVulnerabilities.length());
                    }

                    listener.getLogger().println(message);

                    if (failOnHighVulns || failOnHighMediumVulns) {
                        if (highVulnerabilities.length() > 0 || mediumVulnerabilities.length() > 0) {
                            throw new RuntimeException(
                                    "High or Medium severity detected in the response. Failing the build.");
                        }
                    }
                    return true;
                }
                listener.getLogger().println("No vulnerabilities found. Build Success.");
                return true;
            }
            return false;
        } catch (JSONException e) {
            e.printStackTrace();
            throw new RuntimeException("Error parsing JSON response: " + e.getMessage());
        }
    }
}
