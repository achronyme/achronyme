<?php
// simple_api.php
// A simple PHP server to test Achronyme HTTP client

header('Content-Type: application/json');

$method = $_SERVER['REQUEST_METHOD'];
$path = $_SERVER['PATH_INFO'] ?? '/';

$response = [
    'status' => 'ok',
    'method' => $method,
    'timestamp' => time()
];

// Read input for POST
if ($method === 'POST') {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    $response['received_data'] = $data;
    $response['message'] = "Data received successfully";
}

// Handle routes
if ($path === '/data') {
    $response['data'] = [
        ['id' => 1, 'value' => 10.5],
        ['id' => 2, 'value' => 20.0],
        ['id' => 3, 'value' => 15.75]
    ];
} elseif ($path === '/echo') {
    // Echo headers
    $response['headers'] = getallheaders();
}

echo json_encode($response);
