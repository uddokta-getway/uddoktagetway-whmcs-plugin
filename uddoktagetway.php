<?php
/**
 * WHMCS uddoktagetway Payment Gateway Module
 * 
 * @package     WHMCS Gateway Modules
 * @author      Uddokta Getway Team
 * @version     3.1.0
 */

if (!defined("WHMCS")) {
    die("This file cannot be accessed directly");
}

function uddoktagetway_MetaData()
{
    return [
        'DisplayName'                 => 'uddoktagetway Payment Gateway',
        'APIVersion'                  => '1.1',
        'DisableLocalCreditCardInput' => true,
        'TokenisedStorage'            => false,
    ];
}

function uddoktagetway_config()
{
    return [
        'FriendlyName' => [
            'Type'  => 'System',
            'Value' => 'uddoktagetway Payment Gateway',
        ],
        'gateway_url' => [
            'FriendlyName' => 'Gateway Base URL',
            'Type'         => 'text',
            'Size'         => '60',
            'Default'      => 'https://uddoktagetway.com',
            'Description'  => 'Base URL of your uddoktagetway Gateway (e.g. https://uddoktagetway.com)',
        ],
        'app_key' => [
            'FriendlyName' => 'App Key',
            'Type'         => 'text',
            'Size'         => '50',
            'Description'  => 'App Key from Merchant Portal > Developer Integration',
        ],
        'app_secret' => [
            'FriendlyName' => 'App Secret',
            'Type'         => 'password',
            'Size'         => '50',
            'Description'  => 'App Secret from Merchant Portal > Developer Integration',
        ],
        'convert_to_bdt' => [
            'FriendlyName' => 'Enable Auto Currency Conversion',
            'Type'         => 'yesno',
            'Default'      => 'on',
            'Description'  => 'Automatically convert foreign currencies (USD, EUR, GBP etc.) to BDT',
        ],
        'exchange_rate' => [
            'FriendlyName' => 'Exchange Rate (1 Foreign Unit = BDT)',
            'Type'         => 'text',
            'Size'         => '10',
            'Default'      => '120.00',
            'Description'  => 'Example: 120.00 means 1 USD = 120 BDT. Set 1 if your currency is already BDT.',
        ],
        'button_text' => [
            'FriendlyName' => 'Pay Button Label',
            'Type'         => 'text',
            'Size'         => '30',
            'Default'      => 'Pay via uddoktagetway',
            'Description'  => 'Text shown on the payment button',
        ],
    ];
}

function uddoktagetway_link($params)
{
    $gatewayUrl   = rtrim($params['gateway_url'] ?: 'https://uddoktagetway.com', '/');
    $appKey       = trim($params['app_key'] ?? '');
    $appSecret    = trim($params['app_secret'] ?? '');
    $buttonText   = htmlspecialchars($params['button_text'] ?: 'Pay via uddoktagetway', ENT_QUOTES, 'UTF-8');
    $exchangeRate = floatval($params['exchange_rate'] ?: 120.00);
    $autoConvert  = (!empty($params['convert_to_bdt']) && in_array($params['convert_to_bdt'], ['on', '1', 'yes']));

    $invoiceId   = (int)$params['invoiceid'];
    $rawAmount   = floatval($params['amount']);
    $currency    = strtoupper(trim($params['currency'] ?? 'BDT'));
    $systemUrl   = rtrim($params['systemurl'], '/');

    $firstname = $params['clientdetails']['firstname'] ?? '';
    $lastname  = $params['clientdetails']['lastname'] ?? '';
    $fullname  = trim($firstname . ' ' . $lastname);
    $email     = $params['clientdetails']['email'] ?? '';
    $phone     = $params['clientdetails']['phonenumber'] ?? '';

    // Currency Conversion
    $payAmount = $rawAmount;
    $appliedRate = 1.0;
    $conversionApplied = false;

    if ($currency !== 'BDT' && ($autoConvert || $exchangeRate > 1.0)) {
        $appliedRate = $exchangeRate > 0 ? $exchangeRate : 1.0;
        $payAmount = round($rawAmount * $appliedRate, 2);
        $conversionApplied = true;
    }

    $formattedPayAmount   = number_format($payAmount, 2, '.', '');
    $formattedWhmcsAmount = number_format($rawAmount, 2, '.', '');
    $merchTxnId           = 'INV-' . $invoiceId . '-' . time();

    // HMAC Signature
    $signaturePayload = $invoiceId . '|' . $merchTxnId . '|' . $formattedWhmcsAmount . '|' . $formattedPayAmount;
    $hmacHash = hash_hmac('sha256', $signaturePayload, $appSecret);

    $callbackUrl = $systemUrl . '/modules/gateways/callback/uddoktagetway.php';
    $queryParams = http_build_query([
        'invoiceid'             => $invoiceId,
        'MerchantTransactionId' => $merchTxnId,
        'whmcs_amount'          => $formattedWhmcsAmount,
        'whmcs_currency'        => $currency,
        'bdt_amount'            => $formattedPayAmount,
        'exchange_rate'         => $appliedRate,
        'hash'                  => $hmacHash,
    ]);

    try {
        $apiClient = new WHMCS_uddoktagetway_API_Client($gatewayUrl, $appKey, $appSecret);

        $payload = [
            'CustomerOrderId'         => (string)$invoiceId,
            'order_id'                => (string)$invoiceId,
            'merchantTransactionId'   => (string)$merchTxnId,
            'merchant_transaction_id' => (string)$merchTxnId,
            'totalAmount'             => (string)$formattedPayAmount,
            'amount'                  => (string)$formattedPayAmount,
            'currency'                => 'BDT',
            'successUrl'              => $callbackUrl . '?' . $queryParams . '&Status=Success',
            'failUrl'                 => $callbackUrl . '?' . $queryParams . '&Status=Failure',
            'cancelUrl'               => $callbackUrl . '?' . $queryParams . '&Status=Cancel',
            'redirect_url'            => $callbackUrl . '?' . $queryParams . '&Status=Success',
            'customerName'            => $fullname ?: 'WHMCS Client',
            'customerEmail'           => $email ?: 'client@example.com',
            'customerPhone'           => $phone ?: '01700000000',
            'metadata'                => [
                'whmcs_invoice_id' => $invoiceId,
                'whmcs_amount'     => $formattedWhmcsAmount,
                'whmcs_currency'   => $currency,
                'client_name'      => $fullname,
                'client_email'     => $email,
                'exchange_rate'    => $appliedRate,
            ],
        ];

        $paymentResponse = $apiClient->initializePayment($payload);

        if (!empty($paymentResponse['RedirectURL'])) {
            $redirectUrl = htmlspecialchars($paymentResponse['RedirectURL'], ENT_QUOTES, 'UTF-8');

            $html  = '<div style="margin:15px 0; text-align:center;">';
            $html .= '<a href="' . $redirectUrl . '" class="btn btn-success" style="background:#006852;border-color:#006852;color:#fff;font-weight:700;padding:12px 28px;border-radius:8px;font-size:15px;text-decoration:none;display:inline-block;box-shadow:0 4px 12px rgba(0,104,82,0.25);">';
            $html .= '<i class="fa fa-lock"></i> ' . $buttonText;

            if ($conversionApplied) {
                $html .= ' (৳' . number_format($payAmount, 2) . ' BDT)';
            } else {
                $html .= ' (৳' . number_format($rawAmount, 2) . ')';
            }
            $html .= '</a>';

            if ($conversionApplied) {
                $html .= '<div style="font-size:12px;color:#555;margin-top:8px;">';
                $html .= 'Conversion: <strong>' . htmlspecialchars($currency) . ' ' . number_format($rawAmount, 2) . '</strong> × ' . number_format($appliedRate, 2) . ' = <strong>৳' . number_format($payAmount, 2) . ' BDT</strong>';
                $html .= '</div>';
            }

            $html .= '</div>';
            return $html;
        }

        return '<div class="alert alert-danger">Unable to initialize payment session.</div>';

    } catch (\Throwable $e) {
        logActivity('uddoktagetway Error: ' . $e->getMessage());
        return '<div class="alert alert-danger">Gateway Error: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . '</div>';
    }
}

class WHMCS_uddoktagetway_API_Client
{
    private $baseUrl;
    private $appKey;
    private $appSecret;

    public function __construct($baseUrl, $appKey, $appSecret)
    {
        $this->baseUrl   = rtrim($baseUrl, '/');
        $this->appKey    = trim((string)$appKey);
        $this->appSecret = trim((string)$appSecret);
    }

    public function initializePayment(array $payload)
    {
        $merchantTxnId = $payload['merchantTransactionId'] ?? $payload['merchant_transaction_id'] ?? ('INV-' . time());
        $orderId       = $payload['CustomerOrderId'] ?? $payload['order_id'] ?? ('ORDER-' . time());
        $amount        = floatval($payload['totalAmount'] ?? $payload['amount'] ?? 0);
        $successUrl    = $payload['successUrl'] ?? $payload['redirect_url'] ?? '';
        $cancelUrl     = $payload['cancelUrl'] ?? '';
        $failUrl       = $payload['failUrl'] ?? '';

        $apiUrl = $this->baseUrl . '/api/v1/transaction/create';

        $apiPayload = [
            'app_key'                 => $this->appKey,
            'app_secret'              => $this->appSecret,
            'merchant_transaction_id' => $merchantTxnId,
            'merchantTransactionId'   => $merchantTxnId,
            'order_id'                => (string)$orderId,
            'CustomerOrderId'         => (string)$orderId,
            'amount'                  => $amount,
            'totalAmount'             => $amount,
            'customer_name'           => $payload['customerName'] ?? 'Customer',
            'customer_email'          => $payload['customerEmail'] ?? '',
            'customer_phone'          => $payload['customerPhone'] ?? '',
            'success_url'             => $successUrl,
            'successUrl'              => $successUrl,
            'cancel_url'              => $cancelUrl,
            'cancelUrl'               => $cancelUrl,
            'fail_url'                => $failUrl,
            'failUrl'                 => $failUrl,
            'redirect_url'            => $successUrl,
            'metadata'                => $payload['metadata'] ?? null,
        ];

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $apiUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($apiPayload),
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'Accept: application/json',
                'X-App-Key: ' . $this->appKey,
                'X-App-Secret: ' . $this->appSecret,
            ],
            CURLOPT_TIMEOUT        => 20,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr  = curl_error($ch);
        curl_close($ch);

        if ($response) {
            $json = json_decode($response, true);

            if ($httpCode === 200) {
                $payUrl = $json['data']['payment_url'] 
                       ?? $json['payment_url'] 
                       ?? $json['RedirectURL'] 
                       ?? $json['redirect_url'] 
                       ?? null;

                if (!empty($payUrl)) {
                    return [
                        'RedirectURL' => $payUrl,
                        'Data'        => $json['data']['transaction_id'] ?? '',
                    ];
                }
            }

            if (!empty($json['message'])) {
                throw new \Exception("API Error (HTTP {$httpCode}): " . $json['message']);
            }
        }

        $errMsg = $curlErr ? "cURL Error: {$curlErr}" : "HTTP Code {$httpCode}";
        throw new \Exception("Payment session creation failed ({$errMsg})");
    }
}
