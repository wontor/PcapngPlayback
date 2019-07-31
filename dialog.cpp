/*
 *  author: wangt@njust.edu.cn
 *  last edited: 2019.07.31
 *
 */

#include "dialog.h"
#include "ui_dialog.h"
#include <QFileDialog>
#include <QHeaderView>
#include <math.h>
#include <QHostAddress>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QTimer>
#include <QProgressDialog>


Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    mp_udpHeader = NULL;
    m_total_rcdnum = 0;

    setWindowTitle("Pcapng Parser & Playback - 20190731");

    m_playbackip = QString("not seted");
    m_playbackPort = QString("not seted");
    m_playing = false;

    m_playback_startnum = -1;
    m_playback_endnum = -1;
    m_playback_speed = 1.0;

    filter_trk_src = -1;
    filter_mode3a = -1;
    filter_trk_no = -1;
    filter_height_max = -1.0;
    filter_range_max = -1.0;


    QStringList twheader;
    twheader<<"Time"<<"Source"<<"Destination"<<"Protocol"<<"Length"<<"pkt idx";
    ui->tw_rcds->setColumnCount(twheader.length());
    ui->tw_rcds->setHorizontalHeaderLabels(twheader);

    ui->tw_rcds->setColumnWidth(0, 200);
    ui->tw_rcds->setColumnWidth(1, 130);
    ui->tw_rcds->setColumnWidth(2, 130);
    ui->tw_rcds->setColumnWidth(3, 100);
    ui->tw_rcds->setColumnWidth(4, 100);

    // ui->tw_rcds->horizontalHeader()->setResizeMode(0,QHeaderView::Fixed);
    ui->tw_rcds->horizontalHeader()->setStretchLastSection(true);

    // ui->tw_rcds->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->tw_rcds->setSelectionBehavior ( QAbstractItemView::SelectRows);
    ui->tw_rcds->setEditTriggers ( QAbstractItemView::NoEditTriggers );

    QTextDocument *doc = ui->pt_data->document();
    QFont font = doc->defaultFont();
    font.setFamily("Courier New");
    font.setPointSize(16);
    doc->setDefaultFont(font);

    ui->splitter_2->setStretchFactor(0, 1);
    ui->splitter_2->setStretchFactor(1, 3);

    m_udpsocket = new QUdpSocket(this);

    QList<QHostAddress>	addrs = QNetworkInterface::allAddresses();

    QListIterator<QHostAddress> i(addrs);
    while (i.hasNext()) {
        QHostAddress addr = i.next();
        if(addr.protocol() == QAbstractSocket::IPv4Protocol
                && addr != QHostAddress::LocalHost){
            ui->cb_ip->addItem(addr.toString());
        }
    }

    //below is unnecessry, on_cb_ip_currentIndexChanged will be invoked when dialog first shown
    //m_udpsocket->bind(QHostAddress(ui->cb_ip->currentText()),0);

    ui->le_playback_destip->setText(ui->cb_ip->currentText());
    ui->le_playback_destport->setText(QString("5010"));
}

Dialog::~Dialog()
{
    if (mp_udpHeader != NULL){
        free_udps(mp_udpHeader);
    }

    if (m_udpsocket != NULL){
        delete m_udpsocket;
    }
    delete ui;
}

void Dialog::showRcds(){

    if(mp_udpHeader == NULL){
        return;
    }

    int filter_start_rcdnum = 0;
    if(ui->cb_filter_startrcd->checkState() == Qt::Checked){
        if(ui->le_filter_start_rcdnum->text() != ""){
            filter_start_rcdnum = ui->le_filter_start_rcdnum->text().toInt();
        }
    }

    int filter_end_rcdnum = m_total_rcdnum;
    if(ui->cb_filter_endrcd->checkState() == Qt::Checked){
        if(ui->le_filter_end_rcdnum->text() != ""){
            filter_end_rcdnum = ui->le_filter_end_rcdnum->text().toInt();
        }
    }

    double filter_start_time = -1;
    if(ui->cb_filter_start_datetime->checkState() == Qt::Checked){
        filter_start_time = ui->dte_filter_start->dateTime().toMSecsSinceEpoch();
    }

    double filter_end_time = -1;
    if(ui->cb_filter_end_datetime->checkState() == Qt::Checked){
        filter_end_time = ui->dte_filter_end->dateTime().toMSecsSinceEpoch();
    }

    QProgressDialog progressdlg("parsing rcd...", "Abort", 0, 100, this);
    progressdlg.setValue(0);
    progressdlg.setWindowModality(Qt::WindowModal);
    int progressstep = m_total_rcdnum/100;

    //clear contents
    ui->tw_rcds->setRowCount(0);

    UDPInfo* pc = mp_udpHeader;
//    uint32_t timestamp_high = mp_udpHeader->timestamp_high;
//    uint32_t timestamp_low = mp_udpHeader->timestamp_low;

    int pktidx = -1;
    while (pc != NULL){
        pktidx += 1;
        if(pktidx % progressstep == 0){
            progressdlg.setValue(pktidx / progressstep);
        }

        if (progressdlg.wasCanceled()){
            break;
        }

        if(pktidx < filter_start_rcdnum){
            pc = pc->next_udp;
            continue;
        }

        if(pktidx > filter_end_rcdnum){
            break;
        }

        double ttime = (pc->timestamp_high*pow(2,32)+pc->timestamp_low)*1e-3;
        if(filter_start_time > 0){
            if(ttime < filter_start_time){
                pc = pc->next_udp;
                continue;
            }
        }

        if(filter_end_time > 0){
            if(ttime > filter_end_time){
                break;
            }
        }

        int row_num = ui->tw_rcds->rowCount();
        ui->tw_rcds->insertRow(row_num);

        // qint64 itime = (pc->timestamp_high - timestamp_high)*(pow(2,32)) + (pc->timestamp_low - timestamp_low);
        // ui->tw_rcds->setItem(row_num, 0, new QTableWidgetItem(/*QString("%1").arg(itime)*/QString::number(itime * 1e-6,'f',6)));

        ui->tw_rcds->setItem(row_num, 0, new QTableWidgetItem(getUdpinfoDatetime(pc).toString("yyyy.MM.dd hh:mm:ss.z")));
        ui->tw_rcds->setItem(row_num, 1, new QTableWidgetItem(QString("%1.%2.%3.%4:%5").arg(pc->src_ip[0]).arg(pc->src_ip[1]).arg(pc->src_ip[2]).arg(pc->src_ip[3]).arg(pc->src_port)));
        ui->tw_rcds->setItem(row_num, 2, new QTableWidgetItem(QString("%1.%2.%3.%4:%5").arg(pc->dest_ip[0]).arg(pc->dest_ip[1]).arg(pc->dest_ip[2]).arg(pc->dest_ip[3]).arg(pc->dest_port)));
        ui->tw_rcds->setItem(row_num, 3, new QTableWidgetItem("UDP"));

        QTableWidgetItem* twi = new QTableWidgetItem(QString("%1").arg(pc->datagram_len));
        twi->setData(1,QVariant::fromValue((void *) pc));
        ui->tw_rcds->setItem(row_num, 4, twi);

        ui->tw_rcds->setItem(row_num, 5, new QTableWidgetItem(QString("%1").arg(pktidx)));

        pc = pc->next_udp;
    }

    progressdlg.setValue(100);
}


void Dialog::on_pb_selfile_clicked(){
    QString fileName = QFileDialog::getOpenFileName(this, "选择Pcapng文件", "","Pcapng File (*.pcapng)");
    if(!fileName.isEmpty()) {
//        qDebug(name.toLatin1());
        ui->le_filename->setText(fileName);
        m_rcdFileName = fileName;

        if (mp_udpHeader != NULL){
            free_udps(mp_udpHeader);
        }

        m_total_rcdnum = parse_file(m_rcdFileName.toLatin1(),&mp_udpHeader);
        if(m_total_rcdnum == 0 || mp_udpHeader == NULL){
            QMessageBox::information(this,"PcapngPlayback","Open and decode file failed!");
            return;
        }
        ui->le_filter_start_rcdnum->setText("0");
        ui->le_filter_end_rcdnum->setText(QString("%1").arg(m_total_rcdnum));

        UDPInfo* lastpc = mp_udpHeader;
        //make some statistics
        UDPInfo* p = mp_udpHeader;

        while(p != NULL){
            lastpc = p;
            p = p->next_udp;
        }

        ui->dte_filter_start->setDateTime(getUdpinfoDatetime(mp_udpHeader));
        ui->dte_filter_end->setDateTime(getUdpinfoDatetime(lastpc).addMSecs(1000));

        showRcds();
    }
}

void Dialog::on_tw_rcds_itemSelectionChanged(){

    int row = ui->tw_rcds->currentRow();
    if(row < 0){
        return;
    }

    QTableWidgetItem *item = ui->tw_rcds->item(row, 4);
    UDPInfo* p = (UDPInfo*)(item->data(1).value<void *>());

    QByteArray qa2((const char*)(p->datagram),p->datagram_len);
    QString qstr(qa2.toHex());
    for(int i=qstr.length();i>0;i-=2){
        qstr.insert(i," ");
    }

    ui->pt_data->clear();
    ui->pt_data->appendHtml("<p style=\"color:blue\">"+qstr/*.toUpper()*/+"</p><br>");


//    try {
//        QString r("<p style=\"color:green\">");

//        r += decode_datagram(p->datagram,p->datagram_len);

//        r += QString("</p>");
//        ui->pt_data->appendHtml(r);
//    } catch(...) {
//        ui->pt_data->appendHtml("<p style=\"color:red\">decode failed</p>");
//    }

//    ui->pt_data->appendHtml("<p style=\"color:grey\">decoded not supported now</p>");
}

void Dialog::on_cb_ip_currentIndexChanged(int index){
    int bindport = 0;
    if(ui->cb_playback_srcport->checkState() == Qt::Checked){
        if(ui->le_playback_srcport->text() != ""){
            bindport = ui->le_playback_srcport->text().toInt();
        }
    }
    m_udpsocket->bind(QHostAddress(ui->cb_ip->currentText()),bindport);
}

void Dialog::on_tw_rcds_itemDoubleClicked(QTableWidgetItem *item){
    int row = ui->tw_rcds->currentRow();
    QTableWidgetItem *item4 = ui->tw_rcds->item(row, 4);
    UDPInfo* p = (UDPInfo*)(item4->data(1).value<void *>());

    playback((const char *)p->datagram,p->datagram_len);
}

bool Dialog::playback(const char* datagram, int len){
    QString ip = ui->le_playback_destip->text();
    if (m_playbackip != ip){
        if (ip == ""){
            QMessageBox msgBox;
            msgBox.setText("请设置回放IP");
            msgBox.exec();

            ui->le_playback_destip->setFocus();
            return false;
        }

        //if older is multicast,leave it.
        if (QHostAddress(m_playbackip).isMulticast()){
            m_udpsocket->leaveMulticastGroup(QHostAddress(m_playbackip));
        }

        //set new playback ip
        m_playbackip = ip;

        if (QHostAddress(m_playbackip).isMulticast()){
            QNetworkInterface interface = Addr2Interface(QHostAddress(ui->cb_ip->currentText()));
            m_udpsocket->joinMulticastGroup(QHostAddress(m_playbackip),interface);
        }
    }

    QString port = ui->le_playback_destport->text();
    if(m_playbackPort != port){
        if(port == ""){
            QMessageBox msgBox;
            msgBox.setText("请设置回放Port");
            msgBox.exec();

            ui->le_playback_destport->setFocus();
            return false;
        }

        m_playbackPort = port;
    }

    m_udpsocket->writeDatagram(datagram,len,QHostAddress(m_playbackip), m_playbackPort.toInt());
    return true;
}
void Dialog::on_btn_plbstart_clicked(){
    m_playing = !m_playing;

    if(m_playing){
        if(ui->tw_rcds->rowCount() <= 0){
            QMessageBox msgBox;
            msgBox.setText("请打开有效的数据文件");
            msgBox.exec();
            m_playing = false;
            return;
        }

        m_playback_startnum = -1;
        m_playback_endnum = -1;
        m_playback_speed = 1.0;

        if(ui->cb_startrcd->checkState() == Qt::Checked){
            if(ui->le_start_rcdnum->text() != ""){
                m_playback_startnum = ui->le_start_rcdnum->text().toInt();
                if(m_playback_startnum >= 0){
                    ui->tw_rcds->setCurrentCell(m_playback_startnum,QItemSelectionModel::Select);
                }
            }
        }

        if(ui->cb_endrcd->checkState() == Qt::Checked){
            if(ui->le_end_rcdnum->text() != ""){
                m_playback_endnum = ui->le_end_rcdnum->text().toInt();
            }
        }

        if(ui->cb_playbackspeed->checkState() == Qt::Checked){
            m_playback_speed = ui->dsb_playback_speed->text().toFloat();
            qDebug()<<"m_playback_speed"<<m_playback_speed;
        }

        QTimer::singleShot(0, this, SLOT(on_timer()));
        ui->btn_plbstart->setText("停止回放");
    } else {
        ui->btn_plbstart->setText("开始回放");
    }
}

void Dialog::on_timer(){
    int row = ui->tw_rcds->currentRow();
    if (row < 0){
        row = 0;
    }

    if(m_playback_endnum > 0 && row > m_playback_endnum){
        m_playing = false;
        ui->btn_plbstart->setText("开始回放");
        return;
    }

    qDebug()<<"current row:"<<row;

    QTableWidgetItem *item4 = ui->tw_rcds->item(row, 4);
    UDPInfo* p = (UDPInfo*)(item4->data(1).value<void *>());
    if(!playback((const char *)p->datagram,p->datagram_len)){
        ui->btn_plbstart->setText("开始回放");
        m_playing = false;
        return;
    }

    uint32_t timestamp_high = p->timestamp_high;
    uint32_t timestamp_low = p->timestamp_low;

    if(row+1 < ui->tw_rcds->rowCount()){
        item4 = ui->tw_rcds->item(row+1, 4);
        p = (UDPInfo*)(item4->data(1).value<void *>());

        qint64 itime = (p->timestamp_high - timestamp_high)*(pow(2,32)) + (p->timestamp_low - timestamp_low);

        if(m_playing){
            QTimer::singleShot(itime * 1e-3 / m_playback_speed, this, SLOT(on_timer()));
        }

        ui->tw_rcds->setCurrentCell(row+1,QItemSelectionModel::Select);
    } else {
        m_playing = false;
        ui->btn_plbstart->setText("开始回放");
    }
}

void Dialog::on_btn_filter_clicked(){
    showRcds();
}

void Dialog::on_cb_filter_startrcd_stateChanged(int state){
    ui->le_filter_start_rcdnum->setEnabled(state == Qt::Checked);
}

void Dialog::on_cb_filter_endrcd_stateChanged(int state){
    ui->le_filter_end_rcdnum->setEnabled(state == Qt::Checked);
}

void Dialog::on_cb_filter_start_datetime_stateChanged(int state){
    ui->dte_filter_start->setEnabled(state == Qt::Checked);
}

void Dialog::on_cb_filter_end_datetime_stateChanged(int state){
    ui->dte_filter_end->setEnabled(state == Qt::Checked);
}

void Dialog::on_cb_startrcd_stateChanged(int state){
    ui->le_start_rcdnum->setEnabled(state == Qt::Checked);
}

void Dialog::on_cb_endrcd_stateChanged(int state){
    ui->le_end_rcdnum->setEnabled(state == Qt::Checked);
}

void Dialog::on_cb_playbackspeed_stateChanged(int state){
    ui->dsb_playback_speed->setEnabled(state == Qt::Checked);
}

void Dialog::on_cb_playback_srcport_stateChanged(int state){
    ui->le_playback_srcport->setEnabled(state == Qt::Checked);
}
