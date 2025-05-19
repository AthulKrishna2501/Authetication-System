Two-Factor Authentication System
Overview
This project implements a Two-Factor Authentication (2FA) system using Time-Based One-Time Passwords (TOTP). It allows users to enable 2FA by scanning a QR code or entering a TOTP secret manually. The system is built with Go, using the Gin framework, MongoDB for data storage, Neo4j for graph-based user relationships, and Firebase for authentication. QR codes are generated using the skip2/go-qrcode library and served via a temporary link that expires after 15 minutes.
Features

Enable/disable 2FA via a REST API.
Generate and serve TOTP QR codes with expiration.
Store QR code data in MongoDB with a TTL index.
Update user 2FA status in MongoDB and Neo4j.
Secure endpoints with JWT-based authentication.
Render a web page for QR code scanning and manual secret entry.

Prerequisites

Go 1.20 or later
MongoDB 5.0 or later
Neo4j 5.0 or later
Firebase project with Authentication enabled
TextMagic account for SMS (optional, for password resets)
Environment variables configured in .env

Installation
1. Clone the Repository
git clone <repository-url>
cd <repository-directory>

2. Install Dependencies
go mod tidy

Key dependencies:

github.com/gin-gonic/gin
go.mongodb.org/mongo-driver/mongo
github.com/neo4j/neo4j-go-driver/v5
firebase.google.com/go/v4
github.com/pquerna/otp
github.com/skip2/go-qrcode

3. Set Up Environment Variables
Create a .env file in the project root:
BASE_URL=http://localhost:2500
PORT=2500
MONGO_URI=mongodb://localhost:27017
NEO4J_URI=neo4j://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=password
FIREBASE_CREDENTIALS_PATH=/path/to/firebase-credentials.json
TEXTMAGIC_API_KEY=your-textmagic-api-key
TEXTMAGIC_USERNAME=your-textmagic-username
TEXTMAGIC_SENDER_ID=your-textmagic-sender-id

4. Set Up MongoDB

Ensure MongoDB is running.
Create a database named auth with collections users and qrcodes.
Set up a TTL index on qrcodes:db.qrcodes.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 })



5. Set Up Neo4j

Ensure Neo4j is running.
Create a User node for each user with a uid property.

6. Set Up Firebase

Download your Firebase service account credentials and place them at the path specified in FIREBASE_CREDENTIALS_PATH.
Enable Firebase Authentication in your project.

7. Create Template Directory

Create a templates directory in the project root.
Add index.html (provided in the project or below) to templates/:<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Two-Factor Authentication Setup</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
        }
        h1 { color: #333; }
        img { margin: 20px 0; border: 1px solid #ccc; padding: 10px; background-color: #fff; }
        p { color: #555; font-size: 16px; }
        .error { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Setup Two-Factor Authentication</h1>
    <p>Scan the QR code below with your authenticator app:</p>
    <img src="/2fa/qr/{{.token}}/image" alt="QR Code">
    <p>Or enter this secret manually: <strong>{{.secret}}</strong></p>
</body>
</html>



8. Sync Server Clock
Ensure the server clock is synchronized:
sudo ntpdate pool.ntp.org
date

Usage
1. Run the Server
go run main.go

The server will start on http://localhost:2500.
2. Enable 2FA

Endpoint: POST /auth/enable-2fa
Headers:
Content-Type: application/json
Authorization: Bearer <JWT_TOKEN>


Body:{
    "enable": true
}


Response (200):{
    "message": "Two-factor authentication updated successfully",
    "qrLink": "http://localhost:2500/2fa/qr/<32-char-token>"
}



3. Access QR Code Page

Open the qrLink in a browser to view the QR code and TOTP secret.
Scan the QR code with an authenticator app (e.g., Google Authenticator) or enter the secret manually.

4. Verify 2FA

Endpoint: POST /auth/verify-2fa
Headers:
Content-Type: application/json
Authorization: Bearer <JWT_TOKEN>


Body:{
    "code": "123456"
}


Response (200):{
    "message": "Two-factor authentication verified successfully"
}



Project Structure
.
├── main.go
├── handlers
│   └── auth.go
├── utils
│   └── utils.go
├── models
│   └── user.go
├── requests
│   └── two_factor.go
├── templates
│   └── index.html
├── .env
└── go.mod


handlers/auth.go: Contains EnableTwoFactorAuthentication, ServeQRCodePage, and ServeQRCodeImage handlers.
utils/utils.go: Utility functions for TOTP secret generation, QR code creation, and MongoDB storage.
templates/index.html: HTML template for rendering the QR code page.
main.go: Initializes Gin, MongoDB, Neo4j, and Firebase, and defines routes.

Testing
1. Verify MongoDB Document
After enabling 2FA, check the qrcodes collection:
db.qrcodes.findOne({ "token": "<32-char-token>" })

Expected:
{
    "_id": ObjectId("..."),
    "token": "<32-char-token>",
    "uid": "<user-uid>",
    "secret": "<totp-secret>",
    "qrCodeData": { "$binary": "<base64-encoded-png>", "$type": "00" },
    "created_at": ISODate("2025-05-17T10:40:00Z"),
    "expires_at": ISODate("2025-05-17T10:55:00Z")
}

2. Test QR Code Image
Access:
http://localhost:2500/2fa/qr/<32-char-token>/image

Should return a valid PNG image.
3. Postman Test
Test enabling 2FA and accessing the QR code page:
pm.test("Enable 2FA - Success", function () {
    pm.response.to.have.status(200);
    var jsonData = pm.response.json();
    pm.expect(jsonData).to.have.property("message").and.equal("Two-factor authentication updated successfully");
    pm.expect(jsonData).to.have.property("qrLink").and.match(/^http:\/\/localhost:2500\/2fa\/qr\/[0-9a-f]{32}$/);
    
    pm.environment.set("qr_link", jsonData.qrLink);
    pm.sendRequest({
        url: jsonData.qrLink,
        method: "GET"
    }, function (err, res) {
        pm.expect(res).to.have.status(200);
    });
});

4. Manual Testing

Enable 2FA via the API.
Open the QR code link in a browser.
Scan the QR code with an authenticator app.
Verify the TOTP code using the verify-2fa endpoint.

Troubleshooting

Empty QR Code Image:

Check MongoDB qrCodeData field for the token.
Verify logs for Generated QR code and Serving QR code image.
Access /2fa/qr/<token>/image directly and save the response to check if it’s a valid PNG.


Template Errors:

Ensure templates/index.html uses {{.token}} and not ${token}.
Verify Gin loads templates: r.LoadHTMLGlob("templates/*").


MongoDB Issues:

Confirm TTL index on qrcodes.expires_at.
Clear collection if corrupted: db.qrcodes.deleteMany({}).


Logs:

Check for errors in Stored QR code token, Serving QR code page, or Serving QR code image.



Security Notes

JWT Tokens: Ensure JWT tokens are validated with Firebase Authentication.
QR Code Expiration: QR codes expire after 15 minutes via MongoDB TTL.
Production: Implement single-use QR code deletion in ServeQRCodeImage.
Secrets: Store sensitive data (e.g., Firebase credentials, TextMagic API key) securely.

Contributing

Fork the repository.
Create a feature branch: git checkout -b feature-name.
Commit changes: git commit -m "Add feature".
Push to the branch: git push origin feature-name.
Open a pull request.

License
MIT License. See LICENSE for details.
