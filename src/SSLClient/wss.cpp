#define _ETHERNET_WEBSERVER_LOGLEVEL_     0

#include "libb64/base64.h"
#include "detail/Debug.h"
#include "SSLClient/wss.h"
/*
Client& client,
        const br_x509_trust_anchor *trust_anchors,
        const size_t trust_anchors_num,
        const size_t max_sessions = 1,
        const DebugLevel debug = SSL_WARN*/
WSSClient::WSSClient(
    Client& aClient,
    const br_x509_trust_anchor *aTrust_anchors,
    const size_t aTrust_anchors_num,
    const size_t aMax_sessions,
    const DebugLevel aDebug
) : EthernetSSLClient(aClient, aTrust_anchors, aTrust_anchors_num, aMax_sessions, aDebug),
    iTxStarted(false),
    iRxSize(0)
{}

int WSSClient::begin(const char* aPath) {
  // start the GET request
  beginRequest();
  connectionKeepAlive();
  
  int status = get(aPath);

  if (status == 0) {
    uint8_t randomKey[16];
    char base64RandomKey[25];

    // create a random key for the connection upgrade
    for (int i = 0; i < (int)sizeof(randomKey); i++) {
      randomKey[i] = random(0x01, 0xff);
    }
    
    memset(base64RandomKey, 0x00, sizeof(base64RandomKey));
    base64_encode(randomKey, sizeof(randomKey), (unsigned char*)base64RandomKey, sizeof(base64RandomKey));

    // start the connection upgrade sequence
    sendHeader("Upgrade", "websocket");
    sendHeader("Connection", "Upgrade");
    sendHeader("Sec-WebSocket-Key", base64RandomKey);
    sendHeader("Sec-WebSocket-Version", "13");
    endRequest();

    status = responseStatusCode();

    if (status > 0) {
      skipResponseHeaders();
    }
  }

  iRxSize = 0;

  // status code of 101 means success
  return (status == 101) ? 0 : status;
}

int WSSClient::begin(const String& aPath) {
  return begin(aPath.c_str());
}

int WSSClient::beginMessage(int aType) {
  if (iTxStarted) {
    // fail TX already started
    return 1;
  }

  iTxStarted = true;
  iTxMessageType = (aType & 0xf);
  iTxSize = 0;

  return 0;
}

int WSSClient::endMessage() {
  if (!iTxStarted) {
    // fail TX not started
    return 1;
  }

  // send FIN + the message type (opcode)
  EthernetSSLClient::write(0x80 | iTxMessageType);

  // the message is masked (0x80)
  // send the length
  if (iTxSize < 126) {
    EthernetSSLClient::write(0x80 | (uint8_t)iTxSize);
  }
  else if (iTxSize < 0xffff) {
    EthernetSSLClient::write(0x80 | 126);
    EthernetSSLClient::write((iTxSize >> 8) & 0xff);
    EthernetSSLClient::write((iTxSize >> 0) & 0xff);
  } else {
    EthernetSSLClient::write(0x80 | 127);
    EthernetSSLClient::write((iTxSize >> 56) & 0xff);
    EthernetSSLClient::write((iTxSize >> 48) & 0xff);
    EthernetSSLClient::write((iTxSize >> 40) & 0xff);
    EthernetSSLClient::write((iTxSize >> 32) & 0xff);
    EthernetSSLClient::write((iTxSize >> 24) & 0xff);
    EthernetSSLClient::write((iTxSize >> 16) & 0xff);
    EthernetSSLClient::write((iTxSize >>  8) & 0xff);
    EthernetSSLClient::write((iTxSize >>  0) & 0xff);
  }

  uint8_t maskKey[4];

  // create a random mask for the data and send
  for (int i = 0; i < (int)sizeof(maskKey); i++) {
    maskKey[i] = random(0xff);
  }
  
  EthernetSSLClient::write(maskKey, sizeof(maskKey));

  // mask the data and send
  for (int i = 0; i < (int)iTxSize; i++) {
    iTxBuffer[i] ^= maskKey[i % sizeof(maskKey)];
  }

  size_t txSize = iTxSize;

  iTxStarted = false;
  iTxSize = 0;

  return (EthernetSSLClient::write(iTxBuffer, txSize) == txSize) ? 0 : 1;
}

size_t WSSClient::write(uint8_t aByte) {
  return write(&aByte, sizeof(aByte));
}

size_t WSSClient::write(const uint8_t *aBuffer, size_t aSize) {
  if (iState < eReadingBody) {
    // have not upgraded the connection yet
    return EthernetSSLClient::write(aBuffer, aSize);
  }

  if (!iTxStarted)
  {
    // fail TX not   started
    return 0;
  }

  // check if the write size, fits in the buffer
  if ((iTxSize + aSize) > sizeof(iTxBuffer))
  {
    aSize = sizeof(iTxSize) - iTxSize;
  }

  // copy data into the buffer
  memcpy(iTxBuffer + iTxSize, aBuffer, aSize);

  iTxSize += aSize;

  return aSize;
}

int WSSClient::parseMessage()
{
  flushRx();

  // make sure 2 bytes (opcode + length)
  // are available
  if (EthernetSSLClient::available() < 2)
  {
    return 0;
  }

  // read open code and length
  uint8_t opcode = EthernetSSLClient::read();
  int length = EthernetSSLClient::read();

  if ((opcode & 0x0f) == 0)
  {
    // continuation, use previous opcode and update flags
    iRxOpCode |= opcode;
  }
  else
  {
    iRxOpCode = opcode;
  }

  iRxMasked = (length & 0x80);
  length   &= 0x7f;

  // read the RX size
  if (length < 126)
  {
    iRxSize = length;
  }
  else if (length == 126)
  {
    iRxSize = (EthernetSSLClient::read() << 8) | EthernetSSLClient::read();
  }
  else
  {
    iRxSize =   ((uint64_t)EthernetSSLClient::read() << 56) |
                ((uint64_t)EthernetSSLClient::read() << 48) |
                ((uint64_t)EthernetSSLClient::read() << 40) |
                ((uint64_t)EthernetSSLClient::read() << 32) |
                ((uint64_t)EthernetSSLClient::read() << 24) |
                ((uint64_t)EthernetSSLClient::read() << 16) |
                ((uint64_t)EthernetSSLClient::read() << 8)  |
                (uint64_t)EthernetSSLClient::read();
  }

  // read in the mask, if present
  if (iRxMasked)
  {
    for (int i = 0; i < (int)sizeof(iRxMaskKey); i++)
    {
      iRxMaskKey[i] = EthernetSSLClient::read();
    }
  }

  iRxMaskIndex = 0;

  if (TYPE_CONNECTION_CLOSE == messageType())
  {
    flushRx();
    stop();
    iRxSize = 0;
  }
  else if (TYPE_PING == messageType())
  {
    beginMessage(TYPE_PONG);
    
    while (available())
    {
      write(read());
    }
    
    endMessage();

    iRxSize = 0;
  }
  else if (TYPE_PONG == messageType())
  {
    flushRx();
    iRxSize = 0;
  }

  return iRxSize;
}

int WSSClient::messageType()
{
  return (iRxOpCode & 0x0f);
}

bool WSSClient::isFinal()
{
  return ((iRxOpCode & 0x80) != 0);
}

String WSSClient::readString()
{
  int avail = available();
  String s;

  if (avail > 0)
  {
    s.reserve(avail);

    for (int i = 0; i < avail; i++)
    {
      s += (char)read();
    }
  }

  return s;
}

int WSSClient::ping()
{
  uint8_t pingData[16];

  // create random data for the ping
  for (int i = 0; i < (int)sizeof(pingData); i++)
  {
    pingData[i] = random(0xff);
  }

  beginMessage(TYPE_PING);
  write(pingData, sizeof(pingData));
  
  return endMessage();
}

int WSSClient::available()
{
  if (iState < eReadingBody)
  {
    return EthernetSSLClient::available();
  }

  return iRxSize;
}

int WSSClient::read()
{
  byte b;

  if (read(&b, sizeof(b)))
  {
    return b;
  }

  return -1;
}

int WSSClient::read(uint8_t *aBuffer, size_t aSize)
{
  int readCount = EthernetSSLClient::read(aBuffer, aSize);

  if (readCount > 0)
  {
    iRxSize -= readCount;

    // unmask the RX data if needed
    if (iRxMasked)
    {
      for (int i = 0; i < (int)aSize; i++, iRxMaskIndex++)
      {
        aBuffer[i] ^= iRxMaskKey[iRxMaskIndex % sizeof(iRxMaskKey)];
      }
    }
  }

  return readCount;
}

int WSSClient::peek()
{
  int p = EthernetSSLClient::peek();

  if (p != -1 && iRxMasked)
  {
    // unmask the RX data if needed
    p = (uint8_t)p ^ iRxMaskKey[iRxMaskIndex % sizeof(iRxMaskKey)];
  }

  return p;
}

void WSSClient::flushRx()
{
  while (available())
  {
    read();
  }
}
