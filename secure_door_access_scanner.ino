/**
 * @file secure_door_access_scanner.ino
 * @author Nirmal Sunny (nirmal.sunny@study.beds.ac.uk)
 * @author Ervis Paso
 * @brief The program let the ESP8266 to connect to wifi, make requests to server, parse the response from server
 * and to decide whether or not to give the access for user who scanned a card.
 * @version 0.1
 * @date 2022-04-01
 *
 * @copyright Copyright (c) 2022
 *
 */

// Include the essential libraries
#include <string>
#include <Arduino.h>

// Include the Servo library
#include <Servo.h>

// Libraries neccessary for ESP8266 to connect to wifi and make requests
#include <ESP8266WiFi.h>
#include <ESP8266WiFiMulti.h>
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>

// Libraries essential for the card reader
#include <SPI.h>
#include <MFRC522.h>

// Library to parse JSON
#include <ArduinoJson.h>

// Define the card reader pins
#define SS_PIN D8
#define RST_PIN D3

// Define LED pins
#define RED_LED D0
#define GREEN_LED D1

// Declare the Servo pin
int servoPin = D2;

// Create a servo object
Servo Servo1;

// Create a WiFi and http objects
ESP8266WiFiMulti WiFiMulti;
WiFiClient client;
HTTPClient http;

// Initialise the JSON object
DynamicJsonBuffer jsonBuffer;

// Instance of the MFRC522 class of the card reader
MFRC522 rfid(SS_PIN, RST_PIN);
MFRC522::MIFARE_Key key;

/**
 * @brief The below variables might need configuration on setup
 *
 */

// The asset id of this particular scanner.
// It needs to be changed accordingly.
String asset_id = "1";

// The IP address or domain name for the client to connect to.
String HOST = "x.x.x.x";

// WIFi credentials
String wifi_username = "-------";
String wifi_password = "-------";

// An empty variable to store the hardware token on the fly.
String asset_token;

// Set this to true to debug and output logs
bool debug = true;

/**
 * @brief ------- The end of configuration ---------------------
 *
 */

void setup()
{
  if (debug)
  {
    Serial.begin(115200);
    Serial.setDebugOutput(true);
  }

  pinMode(RED_LED, OUTPUT);   // Initialize the LED pin as an output for red LED
  pinMode(GREEN_LED, OUTPUT); // Initialize the LED pin as an output for green LED

  Servo1.attach(servoPin); // We need to attach the servo to the pin number

  /* for (uint8_t t = 4; t > 0; t--)
  {
    Serial.printf("[SETUP] WAIT %d...\n", t);
    Serial.flush();
    delay(1000);
  } */

  // Connecting the wifi
  WiFi.mode(WIFI_STA);
  WiFiMulti.addAP(wifi_username, wifi_password);

  // wait for WiFi connection
  if ((WiFiMulti.run() == WL_CONNECTED))
  {
    if (debug)
    {
      Serial.print("[HTTP] begin...\n");
    }

    // Make the first request to get the asset token
    if (http.begin(client, "http://" + HOST + "/init"))
    {
      if (debug)
      {
        Serial.print("[HTTP] POST request to get token...\n");
      }

      // start connection and send HTTP header
      http.addHeader("Content-Type", "application/json");
      int httpCode = http.POST("{\"asset_id\":\"" + asset_id + "\"}");

      // httpCode will be negative on error
      if (httpCode > 0)
      {
        // HTTP header has been send and Server response header has been handled
        if (debug)
        {
          Serial.printf("[HTTP] POST... code: %d\n", httpCode);
        }

        // We have got 200 or 301 from the server
        if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY)
        {
          String payload = http.getString();
          if (debug)
          {
            Serial.print("[HTTP] The server responded with...\n");
            Serial.println(payload);
          }

          // Parse the response
          JsonObject &asset_response = jsonBuffer.parseObject(payload);
          if (asset_response[String("suceess")] == "true")
            asset_token = to_string(asset_response[String("token")]);
          blinkGreen();
        }
      }
      else
      {
        blinkRed();
        if (debug)
        {
          Serial.printf("[HTTP] POST... failed, error: %s\n", http.errorToString(httpCode).c_str());
          String payload = http.getString();
          if (payload)
          {
            Serial.print("[HTTP] The server responded with...\n");
            Serial.println(payload);
          }
        }
        else
        {
          blinkRed();
          if (debug)
          {
            Serial.print("There was a problem communicating with the server");
          }
        }
      }

      http.end();
    }
    else
    {
      blinkRed();
      if (debug)
      {
        Serial.printf("[HTTP} Unable to connect\n");
      }
    }
  }

  delay(1000);

  SPI.begin();     // Init SPI bus
  rfid.PCD_Init(); // Init MFRC522

  for (byte i = 0; i < 6; i++)
  {
    key.keyByte[i] = 0xFF;
  }

  if (debug)
  {
    Serial.println(F("This code scan the MIFARE Classsic NUID."));
    Serial.print(F("Using the following key:"));
    printHex(key.keyByte, MFRC522::MF_KEY_SIZE);
  }
}

void loop()
{
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  if (!rfid.PICC_IsNewCardPresent())
    return;

  // Verify if the NUID has been readed
  if (!rfid.PICC_ReadCardSerial())
    return;

  MFRC522::PICC_Type piccType = rfid.PICC_GetType(rfid.uid.sak);

  if (debug)
  {
    Serial.print(F("PICC type: "));
    Serial.println(rfid.PICC_GetTypeName(piccType));
  }

  // Check is the PICC of Classic MIFARE type
  if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI &&
      piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
      piccType != MFRC522::PICC_TYPE_MIFARE_4K)
  {
    blinkRed();
    if (debug)
    {
      Serial.println(F("Your tag is not of type MIFARE Classic."));
    }
    return;
  }

  if (debug)
  {
    Serial.println(F("A new card has been detected."));
    Serial.println(F("The NUID tag is:"));
    Serial.print(F("In hex: "));
    Serial.println(returnHex(rfid.uid.uidByte, rfid.uid.size));
  }

  if (http.begin(client, "http://" + HOST + "/access"))
  {
    if (debug)
    {
      Serial.print("[HTTP] POST request to check access...\n");
    }

    // start connection and send HTTP header and body
    http.addHeader("Content-Type", "application/json");
    http.addHeader("x-asset-token", asset_token);
    int httpCode = http.POST("{\"asset_id\":\"" + asset_id + "\", \"uid\":\"" + returnHex(rfid.uid.uidByte, rfid.uid.size) + "\"}");

    // httpCode will be negative on error
    if (httpCode > 0)
    {
      if (debug)
      {
        // HTTP header has been send and Server response header has been handled
        Serial.printf("[HTTP] GET... code: %d\n", httpCode);
      }

      // file found at server
      if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY)
      {
        String payload = http.getString();
        JsonObject &root = jsonBuffer.parseObject(payload);

        if (debug)
        {
          Serial.print("[HTTP] The server responded with...\n");
          Serial.println(payload);
        }

        if (root[String("access")] == "granted")
        {
          if (debug)
          {
            Serial.println("The access was granted");
          }
          grantAccess(); // this fumction has the logic for lock/unlock mechanism
        }
        else
        {
          if (debug)
          {
            Serial.println("The access was declined");
          }
          declineAccess();
        }
      }
    }
    else
    {
      if (debug)
      {
        Serial.printf("[HTTP] GET... failed, error: %s\n", http.errorToString(httpCode).c_str());
        String payload = http.getString();
        Serial.println(payload);
      }
      blinkRed();
    }

    http.end();
  }
  else
  {
    if (debug)
    {
      Serial.printf("[HTTP} Unable to connect\n");
    }
    blinkRed();
  }
  if (debug)
  {
    Serial.println();
    Serial.print(F("In dec: "));
    printDec(rfid.uid.uidByte, rfid.uid.size);
    Serial.println();
  }

  // Halt PICC
  rfid.PICC_HaltA();

  // Stop encryption on PCD
  rfid.PCD_StopCrypto1();
}

/**
 * Helper routine to dump a byte array as hex values to Serial.
 */
void printHex(byte *buffer, byte bufferSize)
{
  for (byte i = 0; i < bufferSize; i++)
  {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}

/**
 * @brief Helper function to return the hex value of uid
 *
 * @param buffer
 * @param bufferSize
 * @return String
 */
String returnHex(byte *buffer, byte bufferSize)
{
  String uid;
  for (byte i = 0; i < bufferSize; i++)
  {
    // Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    uid += (buffer[i] < 0x10 ? "0" : "") + String(buffer[i], HEX);
  }
  return uid;
}

/**
 * Helper routine to dump a byte array as dec values to Serial.
 */
void printDec(byte *buffer, byte bufferSize)
{
  for (byte i = 0; i < bufferSize; i++)
  {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], DEC);
  }
}

/**
 * @brief The logic here to implement lock/unlock mechanism
 *
 */
void grantAccess()
{
  digitalWrite(GREEN_LED, HIGH); // turn the LED on (HIGH is the voltage level)
  delay(1000);                   // wait for a second
  digitalWrite(GREEN_LED, LOW);  // turn the LED off by making the voltage LOW
  delay(100);
  digitalWrite(GREEN_LED, HIGH); // turn the LED off by making the voltage LOW
  delay(100);
  digitalWrite(GREEN_LED, LOW); // turn the LED off by making the voltage LOW
  delay(100);
  digitalWrite(GREEN_LED, HIGH); // turn the LED off by making the voltage LOW
  delay(100);
  digitalWrite(GREEN_LED, LOW); // turn the LED off by making the voltage LOW

  Servo1.write(50);
  // delay(1000);
  //  Make servo go to 90 degrees
  Servo1.write(180);
  delay(3000);
  // Make servo go to 180 degrees
  Servo1.write(0);
  delay(1000);
}

void declineAccess()
{
  digitalWrite(RED_LED, HIGH); // turn the LED on (HIGH is the voltage level)
  delay(1000);                 // wait for a second
  digitalWrite(RED_LED, LOW);  // turn the LED off by making the voltage LOW
  delay(100);
  digitalWrite(RED_LED, HIGH); // turn the LED off by making the voltage LOW
  delay(100);
  digitalWrite(RED_LED, LOW); // turn the LED off by making the voltage LOW
  delay(100);
  digitalWrite(RED_LED, HIGH); // turn the LED off by making the voltage LOW
  delay(100);
  digitalWrite(RED_LED, LOW); // turn the LED off by making the voltage LOW
}

void blinkREd()
{
  digitalWrite(RED_LED, HIGH); // turn the LED on by making the voltage LOW
  delay(800);
  digitalWrite(RED_LED, LOW); // turn the LED off by making the voltage LOW
  delay(800);
  digitalWrite(RED_LED, HIGH); // turn the LED on by making the voltage LOW
  delay(800);
  digitalWrite(RED_LED, LOW); // turn the LED off by making the voltage LOW
}

void blinkGreen()
{
  digitalWrite(GREEN_LED, HIGH); // turn the LED on by making the voltage LOW
  delay(800);
  digitalWrite(GREEN_LED, LOW); // turn the LED off by making the voltage LOW
  delay(800);
  digitalWrite(GREEN_LED, HIGH); // turn the LED on by making the voltage LOW
  delay(800);
  digitalWrite(GREEN_LED, LOW); // turn the LED off by making the voltage LOW
}
