/*
 * Convert ArrayBuffer to hexadecimal string
 */
function bufferToHex(buffer) {

  return [...new Uint8Array(buffer)]
    .map(
      byte =>
        byte.toString(16).padStart(2, "0")
    )
    .join("");

}


/*
 * Generate HMAC SHA-512
 */
async function generateSignature(
  payload,
  secret
) {

  const encoder =
    new TextEncoder();

  const keyData =
    encoder.encode(secret);

  const payloadData =
    encoder.encode(payload);

  const cryptoKey =
    await crypto.subtle.importKey(
      "raw",
      keyData,
      {
        name: "HMAC",
        hash: "SHA-512"
      },
      false,
      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      payloadData
    );

  return bufferToHex(signature);
}


/*
 * Constant-time comparison
 */
function safeEqual(a, b) {

  if (
    typeof a !== "string" ||
    typeof b !== "string"
  ) {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |=
      a.charCodeAt(i) ^
      b.charCodeAt(i);
  }

  return result === 0;
}


export default {

  async fetch(request, env) {

    /*
     * Only POST requests
     */
    if (request.method !== "POST") {

      return new Response(
        JSON.stringify({
          status: false,
          message: "Method not allowed"
        }),
        {
          status: 405,
          headers: {
            "Content-Type":
              "application/json"
          }
        }
      );

    }


    /*
     * IMPORTANT:
     *
     * Read the raw body BEFORE JSON.parse().
     *
     * Paystack signs the raw payload.
     */
    const rawBody =
      await request.text();


    /*
     * Paystack signature
     */
    const receivedSignature =
      request.headers.get(
        "x-paystack-signature"
      );


    if (!receivedSignature) {

      return new Response(
        JSON.stringify({
          status: false,
          message: "Missing Paystack signature"
        }),
        {
          status: 401,
          headers: {
            "Content-Type":
              "application/json"
          }
        }
      );

    }


    /*
     * Generate expected signature
     */
    const expectedSignature =
      await generateSignature(
        rawBody,
        env.PAYSTACK_SECRET_KEY
      );


    /*
     * Verify webhook origin
     */
    if (
      !safeEqual(
        receivedSignature,
        expectedSignature
      )
    ) {

      console.error(
        "Invalid Paystack webhook signature"
      );

      return new Response(
        JSON.stringify({
          status: false,
          message: "Invalid signature"
        }),
        {
          status: 401,
          headers: {
            "Content-Type":
              "application/json"
          }
        }
      );

    }


    /*
     * Parse event AFTER signature verification
     */
    let event;

    try {

      event =
        JSON.parse(rawBody);

    } catch {

      return new Response(
        JSON.stringify({
          status: false,
          message: "Invalid JSON"
        }),
        {
          status: 400,
          headers: {
            "Content-Type":
              "application/json"
          }
        }
      );

    }


    /*
     * Log received event
     */
    console.log(
      "Paystack webhook:",
      JSON.stringify(event)
    );


    /*
     * Process Paystack events
     */
    switch (event.event) {

      case "charge.success":

        await handleSuccessfulPayment(
          event.data,
          env
        );

        break;


      case "charge.failed":

        await handleFailedPayment(
          event.data,
          env
        );

        break;


      case "refund.processed":

        await handleRefund(
          event.data,
          env
        );

        break;


      default:

        console.log(
          `Unhandled Paystack event: ${event.event}`
        );

    }


    /*
     * Acknowledge Paystack immediately
     */
    return new Response(
      JSON.stringify({
        status: true,
        message: "Webhook received"
      }),
      {
        status: 200,
        headers: {
          "Content-Type":
            "application/json"
        }
      }
    );

  }

};


/*
 * SUCCESSFUL PAYMENT
 */
async function handleSuccessfulPayment(
  payment,
  env
) {

  console.log(
    "PAYMENT SUCCESSFUL",
    {
      reference:
        payment.reference,

      amount:
        payment.amount,

      email:
        payment.customer?.email,

      status:
        payment.status,

      metadata:
        payment.metadata
    }
  );


  /*
   * TODO:
   *
   * Save payment to your database.
   *
   * Example:
   *
   * await env.DB.prepare(
   *   `INSERT INTO payments (...) VALUES (...)`
   * ).bind(...).run();
   */

}


/*
 * FAILED PAYMENT
 */
async function handleFailedPayment(
  payment,
  env
) {

  console.log(
    "PAYMENT FAILED",
    {
      reference:
        payment.reference,

      email:
        payment.customer?.email,

      status:
        payment.status
    }
  );

}


/*
 * REFUND
 */
async function handleRefund(
  payment,
  env
) {

  console.log(
    "REFUND PROCESSED",
    payment
  );

}
