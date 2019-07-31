#ifndef UTILS_H
#define UTILS_H
#include "pcapng.h"
#include <QList>
#include <QNetworkInterface>
#include <QHostAddress>
#include <QDatetime>
#include <QString>

#define SWAP16(A)  ((((uint16_t)(A) & 0xff00) >> 8) | \
                    (((uint16_t)(A) & 0x00ff) << 8))
#define SWAP32(A)  ((((uint32_t)(A) & 0xff000000) >> 24) | \
                    (((uint32_t)(A) & 0x00ff0000) >> 8)  | \
                    (((uint32_t)(A) & 0x0000ff00) << 8)  | \
                    (((uint32_t)(A) & 0x000000ff) << 24))

#define PI 3.1415926
#define FL_2_METER 30.413625

extern float RATIO_SPEED;



QString decode_datagram(uint8_t* buff, int buff_len);

QNetworkInterface Addr2Interface(QHostAddress addr);

QDateTime getUdpinfoDatetime(UDPInfo* pc);

#endif // UTILS_H
