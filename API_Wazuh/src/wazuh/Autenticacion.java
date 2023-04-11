/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package wazuh;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 *
 * @author Javier
 */
public class Autenticacion {

    public static void main(String[] args) throws IOException {
        // Cambia estos valores con los tuyos
        String user = "admin";
        String password = "admin";
        String host = "https://192.168.68.116";

        String jwtToken = authenticate(user, password, host);
        System.out.println("JWT token: " + jwtToken);
        
        
    }

    private static String authenticate(String user, String password, String host) throws IOException {
        String credentials = user + ":" + password;
        String encodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
        String authHeader = "Basic " + encodedCredentials;

        URL url = new URL(host + "/security/user/authenticate");
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Authorization", authHeader);

        String body = "{\"module\": \"wazuh-api\"}";
        con.setDoOutput(true);
        try ( OutputStreamWriter writer = new OutputStreamWriter(con.getOutputStream())) {
            writer.write(body);
        }

        int responseCode = con.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            try ( BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                StringBuilder responseBody = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    responseBody.append(line);
                }
                return responseBody.toString();
            }
        } else {
            throw new RuntimeException("Authentication failed with HTTP response code " + responseCode);
        }
    }
}


