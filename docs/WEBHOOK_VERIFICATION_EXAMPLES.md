# Webhook Signature Verification Examples

This guide provides practical code examples in multiple programming languages to help developers securely verify webhook signatures sent by CarbonLedger.

Verifying webhook signatures ensures that incoming requests originate from CarbonLedger and have not been tampered with in transit.

---

## Security Overview

CarbonLedger signs each webhook payload using a pre-shared secret key. Every webhook request includes two custom headers:
1. `X-CarbonLedger-Signature`: The hex-encoded HMAC-SHA256 signature of the payload.
2. `X-CarbonLedger-Timestamp`: The Unix timestamp (in seconds) of when the webhook was sent.

### Replay Attack Prevention
To prevent replay attacks, the signature is computed over the concatenation of the timestamp and the raw request body:
$$\text{Signature} = \text{HMAC-SHA256}(\text{Secret}, \text{Timestamp} + '.' + \text{RawBody})$$

Your server should verify that the signature matches and that the timestamp is within a reasonable tolerance window (e.g., 5 minutes / 300 seconds) of your server's current local time.

---

## Code Examples

### 1. JavaScript / Node.js
```javascript
const crypto = require('crypto');

function verifyWebhook(rawBody, signature, timestamp, secret) {
  // 1. Prevent replay attacks by checking timestamp age (e.g., 5 minutes)
  const fiveMinutesInSeconds = 300;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  if (Math.abs(currentTimestamp - timestamp) > fiveMinutesInSeconds) {
    throw new Error('Request timestamp is outside the tolerance window.');
  }

  // 2. Compute the expected signature
  const signedPayload = `${timestamp}.${rawBody}`;
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(signedPayload)
    .digest('hex');

  // 3. Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSignature, 'hex')
  );
}
```

### 2. Python
```python
import hmac
import hashlib
import time

def verify_webhook(raw_body: str, signature: str, timestamp: int, secret: str) -> bool:
    # 1. Prevent replay attacks by checking timestamp age
    tolerance_seconds = 300
    current_timestamp = int(time.time())
    if abs(current_timestamp - timestamp) > tolerance_seconds:
        raise ValueError("Request timestamp is outside the tolerance window.")

    # 2. Compute the expected signature
    signed_payload = f"{timestamp}.{raw_body}".encode('utf-8')
    expected_signature = hmac.new(
        secret.encode('utf-8'),
        signed_payload,
        hashlib.sha256
    ).hexdigest()

    # 3. Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(signature, expected_signature)
```

### 3. Go
```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"
)

func VerifyWebhook(rawBody string, signature string, timestamp int64, secret string) (bool, error) {
	// 1. Prevent replay attacks by checking timestamp age
	const toleranceSeconds = 300
	currentTimestamp := time.Now().Unix()
	if math.Abs(float64(currentTimestamp-timestamp)) > toleranceSeconds {
		return false, errors.New("request timestamp is outside the tolerance window")
	}

	// 2. Compute the expected signature
	signedPayload := fmt.Sprintf("%d.%s", timestamp, rawBody)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// 3. Constant-time comparison to prevent timing attacks
	sigBytes, err := hex.DecodeString(signature)
	expectedBytes, err2 := hex.DecodeString(expectedSignature)
	if err != nil || err2 != nil {
		return false, errors.New("failed to decode signature hex")
	}

	return hmac.Equal(sigBytes, expectedBytes), nil
}
```

---

## Out-of-Order Webhooks
Webhooks may occasionally be delivered out-of-order due to network retries. To handle this:
- Include a sequence number or version field in your event payload.
- Only process incoming webhook events if the version or sequence number is greater than the last processed event for that specific resource.
