#pragma once
#include <memory>
#include <QVector>
#include <QMutex>
#include <QMainWindow>
#include <tins/tins.h>

namespace Ui {
class Gui;
}

class Gui : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit Gui(QWidget *parent = 0);
    ~Gui();
    void on_packet_recieved(const Tins::IP &ip_packet);
private slots:
    void show_packet_info(const int index);
private:
    Ui::Gui *m_ui;
    QMutex m_mutex;
    QVector<Tins::IP> m_packets;
};

