/*
 *  author: wangt@njust.edu.cn
 *  last edited: 2019.07.31
 *
 */

#include "utils.h"


float decode_net_float4(uint8_t* buff){
    int _v = *(int*)buff;
    _v = SWAP32(_v);
    return *(float*)(&_v);
}

QString decode_datagram(uint8_t* buff, int buff_len){
    // add your own decode code here
}

QNetworkInterface Addr2Interface(QHostAddress addr){
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();

    QListIterator<QNetworkInterface> i(interfaces);
    while (i.hasNext()) {
        QNetworkInterface interface = i.next();
        QList<QNetworkAddressEntry>	entries = interface.addressEntries();

        QListIterator<QNetworkAddressEntry> ie(entries);
        while(ie.hasNext()){
            if(addr == ie.next().ip()){
                //qDebug()<<interface.humanReadableName();
                return interface;
            }
        }
    }

    return QNetworkInterface();
}


QDateTime getUdpinfoDatetime(UDPInfo* pc){
    double ttime = (pc->timestamp_high*pow(2,32)+pc->timestamp_low)*1e-3;
    return QDateTime::fromMSecsSinceEpoch(ttime);
}
