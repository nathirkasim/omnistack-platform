<?php
// SQL Injection (CWE-89)
if (isset($_GET['user_id'])) {
    $conn = mysqli_connect("localhost", "root", "secret", "appdb");
    $id = $_GET['user_id'];
    // VULNERABLE: Direct concatenation of user GET parameter into SQL query (CWE-89)
    $sql = "SELECT username, email FROM users WHERE id = " . $id;
    $result = mysqli_query($conn, $sql);
}

// Command Injection (CWE-78)
if (isset($_GET['ip'])) {
    $ip = $_GET['ip'];
    // VULNERABLE: Direct system shell execution with untrusted input (CWE-78)
    system("ping -c 1 " . $ip);
}

// Local File Inclusion / Path Traversal (CWE-98, CWE-22)
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    // VULNERABLE: Arbitrary file inclusion via user-controlled include path (CWE-98)
    include("templates/" . $page . ".php");
}

// Insecure Deserialization (CWE-502)
if (isset($_COOKIE['session_data'])) {
    // VULNERABLE: Unsanitized unserialize of cookie payload enables PHP object injection (CWE-502)
    $session = unserialize(base64_decode($_COOKIE['session_data']));
}
?>
