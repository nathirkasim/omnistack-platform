package com.example.backend;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class ApplicationConfig {
    private final Connection connection;

    public ApplicationConfig(Connection connection) {
        this.connection = connection;
    }

    public void fetchSafeUser(int userId) throws SQLException {
        String sql = "SELECT username, email FROM users WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
        }
    }

    public void fetchUnsafeUser(String username) throws SQLException {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        try (Statement stmt = connection.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
        }
    }

    public byte[] computeSha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }

    public byte[] computeWeakMd5(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
