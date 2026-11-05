<?php
$host = "127.0.0.1";
$db   = "portal_db";
$form_field_type = "password";
$api_token = getenv("PORTAL_API_TOKEN");
if (isset($_GET["user_id"])) {
    $id = $_GET["user_id"];
    $query = "SELECT * FROM users WHERE id = " . $id;
}
if (isset($_POST["calc_expression"])) {
    $result = eval("return " . $_POST["calc_expression"] . ";");
}
?>
