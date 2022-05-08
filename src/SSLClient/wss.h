#pragma once

#ifndef WSS_H
#define WSS_H

#include <Arduino.h>
#include "detail/Debug.h"
#include "SSLClient/SSLClient.h"

static const int TYPE_CONTINUATION     = 0x0;
static const int TYPE_TEXT             = 0x1;
static const int TYPE_BINARY           = 0x2;
static const int TYPE_CONNECTION_CLOSE = 0x8;
static const int TYPE_PING             = 0x9;
static const int TYPE_PONG             = 0xa;

class WSSClient : public EthernetSSLClient
{
  public:
    WSSClient(
        Client& client,
        const br_x509_trust_anchor *trust_anchors,
        const size_t trust_anchors_num,
        const size_t max_sessions = 1,
        const DebugLevel debug = SSL_WARN
    );

    int begin(const char* aPath = "/");
    int begin(const String& aPath);
    int beginMessage(int aType);
    int endMessage();
    int parseMessage();
    int messageType();
    bool isFinal();
    String readString();
    int ping();
    virtual size_t write(uint8_t aByte);
    virtual size_t write(const uint8_t *aBuffer, size_t aSize);
    virtual int   available();
    virtual int read();
    virtual int read(uint8_t *buf, size_t size);
    virtual int peek();

  private:
    void flushRx();

  private:
    bool      iTxStarted;
    uint8_t   iTxMessageType;
    uint8_t   iTxBuffer[128];
    uint64_t  iTxSize;

    uint8_t   iRxOpCode;
    uint64_t  iRxSize;
    bool      iRxMasked;
    int       iRxMaskIndex;
    uint8_t   iRxMaskKey[4];
};

#endif

