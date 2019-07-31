#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>

#include <QUdpSocket>
#include <QTableWidget>
#include <QTableWidgetItem>
#include "utils.h"


namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = nullptr);
    ~Dialog();


protected:
    bool playback(const char* datagram, int len);
    void showRcds();
    bool filterRcd(UDPInfo* pc);

protected slots:
    void on_pb_selfile_clicked();
    void on_tw_rcds_itemSelectionChanged();
    void on_tw_rcds_itemDoubleClicked(QTableWidgetItem *item);
    void on_cb_ip_currentIndexChanged(int index);
    void on_btn_plbstart_clicked();
    void on_btn_filter_clicked();

    void on_timer();

    void on_cb_filter_startrcd_stateChanged(int state);
    void on_cb_filter_endrcd_stateChanged(int state);
    void on_cb_filter_start_datetime_stateChanged(int state);
    void on_cb_filter_end_datetime_stateChanged(int state);
    void on_cb_startrcd_stateChanged(int state);
    void on_cb_endrcd_stateChanged(int state);
    void on_cb_playbackspeed_stateChanged(int state);
    void on_cb_playback_srcport_stateChanged(int state);

private:
    Ui::Dialog *ui;

    QString m_rcdFileName;
    UDPInfo* mp_udpHeader;
    int m_total_rcdnum;

    QUdpSocket* m_udpsocket;

    QString m_playbackip;
    QString m_playbackPort;
    bool m_playing;

    int m_playback_startnum;
    int m_playback_endnum;
    float m_playback_speed;

    //filter condition
    int filter_trk_src;
    int filter_mode3a;
    int filter_trk_no;
    float filter_height_max;
    float filter_range_max;
};

#endif // DIALOG_H
