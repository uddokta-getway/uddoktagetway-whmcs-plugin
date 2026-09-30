<?php
/**
 * WHMCS uddoktagetway Callback & Webhook Handler
 * Secure Double-Shield Verification (HMAC-SHA256 Signature & Direct Server API Check)
 * 
 * @package     WHMCS Gateway Modules
 * @author      uddoktagetway Integration Team
 * @copyright   Copyright (c) uddoktagetway Payment Gateway
 * @version     3.1.0
 */

// Bootstrap WHMCS Core Architecture
require_once __DIR__ . '/../../../init.php';
require_once __DIR__ . '/../../../includes/gatewayfunctions.php';
require_once __DIR__ . '/../../../includes/invoicefunctions.php';

$gatewayModuleName = "uddoktagetway";
$GATEWAY           = getGatewayVariables($gatewayModuleName);

if (empty($GATEWAY["type"])) {
    die("uddoktagetway Gateway Module is not active in WHMCS.");
}

// Retrieve callback payload parameters (supports GET, POST, and raw JSON input)
$rawJson = @file_get_contents('php://input');
$jsonBody = !empty($rawJson) ? json_decode($rawJson, true) : [];
$params   = array_merge($_GET, $_POST, is_array($jsonBody) ? $jsonBody : []);

$merchTxnId = trim((string)($params['MerchantTransactionId'] ?? ($params['merchantTransactionId'] ?? ($params['merchant_transaction_id'] ?? ''))));
$cleanMerchTxnId = preg_replace('/-R\d+$/i', '', $merchTxnId);

// Resolve Invoice ID
$rawInvoiceId = $params['invoiceid'] ?? ($params['invoice_id'] ?? ($params['CustomerOrderId'] ?? ($params['order_id'] ?? ($params['valueA'] ?? 0))));
$invoiceId    = (int)$rawInvoiceId;

if ($invoiceId <= 0 && !empty($merchTxnId) && preg_match('/(?:INV|ORDER)-(\d+)/i', $merchTxnId, $m)) {
    $invoiceId = (int)$m[1];
}
if ($invoiceId <= 0 && !empty($cleanMerchTxnId) && preg_match('/(?:INV|ORDER)-(\d+)/i', $cleanMerchTxnId, $m)) {
    $invoiceId = (int)$m[1];
}

$txnId      = trim((string)($params['EPSTransactionId'] ?? ($params['TransactionId'] ?? ($params['transaction_id'] ?? ($merchTxnId ?: 'XT_' . time())))));
$status     = strtolower(trim((string)($params['Status'] ?? ($params['status'] ?? ($params['payment_status'] ?? '')))));
$systemUrl  = rtrim($GATEWAY['systemurl'] ?? '', '/');

$appKey     = trim($GATEWAY['app_key'] ?? '');
$appSecret  = trim($GATEWAY['app_secret'] ?? '');
$gatewayUrl = rtrim($GATEWAY['gateway_url'] ?: 'https://uddoktagetway.com', '/');
$verifyUrl  = $gatewayUrl . '/api/v1/transaction/verify';

// Currency Conversion Amounts & Amounts Handling
$fee          = floatval($params['gateway_fee'] ?? ($params['fee'] ?? 0));
$rawAmount    = floatval($params['amount'] ?? ($params['base_amount'] ?? ($params['totalAmount'] ?? 0)));
$whmcsAmount  = isset($params['whmcs_amount']) ? floatval($params['whmcs_amount']) : $rawAmount;
$bdtAmount    = isset($params['bdt_amount']) ? floatval($params['bdt_amount']) : $rawAmount;
$receivedHash = trim((string)($params['hash'] ?? ($params['signature'] ?? '')));

// Validate WHMCS Invoice ID
if (empty($invoiceId)) {
    logTransaction($GATEWAY["name"], $params, "Security Alert: Callback Received Missing or Invalid Invoice ID");
    header("Location: " . $systemUrl . "/clientarea.php");
    exit();
}

$invoiceId = checkCbInvoiceID($invoiceId, $GATEWAY["name"]);

// =========================================================================
// SHIELD 1: Verify HMAC-SHA256 Cryptographic Signature
// =========================================================================
$formattedWhmcsAmount = number_format($whmcsAmount, 2, '.', '');
$formattedBdtAmount   = number_format($bdtAmount, 2, '.', '');

$hmacVerified = false;
if (!empty($receivedHash) && !empty($appSecret)) {
    $candidateSignatures = [
        $invoiceId . '|' . $merchTxnId . '|' . $formattedWhmcsAmount . '|' . $formattedBdtAmount,
        $invoiceId . '|' . $cleanMerchTxnId . '|' . $formattedWhmcsAmount . '|' . $formattedBdtAmount,
        $invoiceId . '|' . $merchTxnId . '|' . $whmcsAmount . '|' . $bdtAmount,
        $invoiceId . '|' . $cleanMerchTxnId . '|' . $whmcsAmount . '|' . $bdtAmount,
    ];

    foreach ($candidateSignatures as $payload) {
        $expectedHash = hash_hmac('sha256', $payload, $appSecret);
        if (hash_equals($expectedHash, $receivedHash)) {
            $hmacVerified = true;
            break;
        }
    }
}

// =========================================================================
// Determine Exact WHMCS Invoice Currency Amount to Credit
// =========================================================================
$amountToCredit = 0.00;
if ($whmcsAmount > 0) {
    $amountToCredit = $whmcsAmount;
} else {
    try {
        if (function_exists('localAPI')) {
            $invoiceResult = localAPI('GetInvoice', ['invoiceid' => $invoiceId]);
            if (!empty($invoiceResult['result']) && $invoiceResult['result'] === 'success' && isset($invoiceResult['balance'])) {
                $amountToCredit = floatval($invoiceResult['balance']);
            }
        }
    } catch (\Throwable $e) {}

    if ($amountToCredit <= 0) {
        $amountToCredit = $rawAmount;
    }
}

// =========================================================================
// SHIELD 2: Direct Server-to-Server REST API Verification
// =========================================================================
$isSuccessStatus = in_array($status, ['success', 'successful', 'completed', '1', 'approved', 'paid']);

if ($isSuccessStatus) {
    
    $apiVerified = false;
    $apiStatus   = '';
    $verifiedTxnId = null;
    $httpCode    = 0;
    $apiErrorMsg = '';

    try {
        $verifyPayload = [
            'app_key'                 => $appKey,
            'app_secret'              => $appSecret,
            'merchant_transaction_id' => $cleanMerchTxnId ?: $merchTxnId,
            'order_id'                => (string)$invoiceId,
        ];
        if (!empty($txnId) && $txnId !== $merchTxnId && $txnId !== $cleanMerchTxnId) {
            $verifyPayload['transaction_id'] = $txnId;
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $verifyUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($verifyPayload),
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Accept: application/json',
                'X-App-Key: ' . $appKey,
                'X-App-Secret: ' . $appSecret,
            ],
            CURLOPT_TIMEOUT        => 20,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_FOLLOWLOCATION => true,
        ]);

        $apiResponse = curl_exec($ch);
        $httpCode    = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr     = curl_error($ch);
        curl_close($ch);

        if ($apiResponse && $httpCode === 200) {
            $apiData = json_decode($apiResponse, true);
            if (!empty($apiData['status']) && $apiData['status'] === 'success') {
                $apiStatus = strtolower(trim((string)($apiData['data']['payment_status'] ?? ($apiData['data']['status'] ?? ''))));
                if (in_array($apiStatus, ['success', 'paid', 'completed', 'approved', '1'])) {
                    $apiVerified = true;
                    if (!empty($apiData['data']['transaction_id'])) {
                        $verifiedTxnId = (string)$apiData['data']['transaction_id'];
                    }
                }
            } else {
                $apiErrorMsg = $apiData['message'] ?? 'Unknown API response format';
            }
        } else {
            $apiErrorMsg = $curlErr ? "cURL Error: {$curlErr}" : "HTTP Code {$httpCode}";
        }

        // Secondary fallback check if first verify attempt with cleanMerchTxnId returned 404
        if (!$apiVerified && $cleanMerchTxnId !== $merchTxnId && !empty($merchTxnId)) {
            $verifyPayload['merchant_transaction_id'] = $merchTxnId;
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $verifyUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => json_encode($verifyPayload),
                CURLOPT_HTTPHEADER     => [
                    'Content-Type: application/json',
                    'Accept: application/json',
                    'X-App-Key: ' . $appKey,
                    'X-App-Secret: ' . $appSecret,
                ],
                CURLOPT_TIMEOUT        => 15,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
            ]);
            $apiResponse = curl_exec($ch);
            $httpCode    = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($apiResponse && $httpCode === 200) {
                $apiData = json_decode($apiResponse, true);
                if (!empty($apiData['status']) && $apiData['status'] === 'success') {
                    $apiStatus = strtolower(trim((string)($apiData['data']['payment_status'] ?? ($apiData['data']['status'] ?? ''))));
                    if (in_array($apiStatus, ['success', 'paid', 'completed', 'approved', '1'])) {
                        $apiVerified = true;
                        if (!empty($apiData['data']['transaction_id'])) {
                            $verifiedTxnId = (string)$apiData['data']['transaction_id'];
                        }
                    }
                }
            }
        }
    } catch (\Throwable $e) {
        logTransaction($GATEWAY["name"], $params, "Server Verification Exception: " . $e->getMessage());
    }

    // Accept payment if Direct Server API verified OR if HMAC verified with success status
    if (!$apiVerified && !$hmacVerified) {
        $diagInfo = "SECURITY FAILURE: Verification refused. API Status: [" . ($apiStatus ?: 'N/A') . "], HTTP Code: [" . $httpCode . "], API Error: [" . ($apiErrorMsg ?: 'None') . "], HMAC: [Failed]";
        logTransaction($GATEWAY["name"], $params, $diagInfo);
        header("Location: " . $systemUrl . "/viewinvoice.php?id=" . $invoiceId . "&paymentfailed=true");
        exit();
    }

    // Determine final unique Transaction ID for WHMCS accounting record
    $finalTxnId = $verifiedTxnId ?: (!empty($txnId) ? $txnId : ($cleanMerchTxnId ?: 'XT_' . $invoiceId . '_' . time()));

    // Check for duplicate transaction processing in WHMCS database
    checkCbTransID($finalTxnId);

    // Record invoice payment in WHMCS database with actual WHMCS invoice currency amount
    addInvoicePayment($invoiceId, $finalTxnId, $amountToCredit, $fee, $gatewayModuleName);

    $logMsg = "Payment Verified & Applied Successfully (" . $amountToCredit . " Credited) [TxnID: " . $finalTxnId . "]";
    if ($bdtAmount > 0 && $whmcsAmount > 0 && $bdtAmount != $whmcsAmount) {
        $logMsg .= " [Converted from BDT " . number_format($bdtAmount, 2) . "]";
    }
    if ($apiVerified && $hmacVerified) {
        $logMsg .= " [Dual-Shield 100% Verified: HMAC + Direct API]";
    } elseif ($apiVerified) {
        $logMsg .= " [Shield 2 Verified: Direct Server API]";
    } else {
        $logMsg .= " [Shield 1 Verified: Cryptographic HMAC Signature]";
    }

    // Log transaction to WHMCS Gateway Activity Log
    logTransaction($GATEWAY["name"], $params, $logMsg);

    // Redirect Client to Invoice Success View
    header("Location: " . $systemUrl . "/viewinvoice.php?id=" . $invoiceId . "&paymentsuccess=true");
    exit();

} elseif (in_array($status, ['cancel', 'cancelled'])) {
    
    // Log cancelled transaction
    logTransaction($GATEWAY["name"], $params, "Payment Cancelled by User for Invoice #" . $invoiceId);

    // Redirect Client to Invoice View without failure alert
    header("Location: " . $systemUrl . "/viewinvoice.php?id=" . $invoiceId . "&paymentcancelled=true");
    exit();
} else {
    
    // Log failed or rejected transaction
    logTransaction($GATEWAY["name"], $params, "Payment Failed or Refused for Invoice #" . $invoiceId . " (Status: " . htmlspecialchars($status, ENT_QUOTES, 'UTF-8') . ")");

    // Redirect Client to Invoice Failed View
    header("Location: " . $systemUrl . "/viewinvoice.php?id=" . $invoiceId . "&paymentfailed=true");
    exit();
}

