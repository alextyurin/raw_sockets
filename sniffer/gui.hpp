#pragma once
#include <memory>
#include <QVector>
#include <QMutex>
#include <QMainWindow>
#include <tins/tins.h>
#include "field.hpp"

class Listener;

namespace Ui {
class Gui;
}

class Gui : public QMainWindow
{
    Q_OBJECT

public:
    explicit Gui(QWidget *parent = 0);
    ~Gui();
    void on_packet_recieved(Tins::PDU *pdu);
private slots:
    void show_packet_info(const int index);
    void start_listening();
    void stop_listening();
    void clear();
    void exit();
    void ascii_radiobutton_clicked();
    void hex_radiobutton_clicked();
    void combobox_changed(const int index);
private:
    void add_table_row(const std::string &attribute, const uint32_t value, const uint8_t bits, const Field::Format format = Field::Format::HEX, const bool is_ip = false);
    QString get_title(Tins::PDU *pdu);
    void clear_table();
    void show_ip_packet_info(const Tins::IP &packet);
    void show_icmp_packet_info(const Tins::ICMP &packet);
    void show_tcp_packet_info(const Tins::TCP &packet);
    void show_udp_packet_info(const Tins::UDP &packet);
    bool check_by_filters(Tins::PDU *pdu);
    void disable_port_form();
    void enable_port_form();
    Ui::Gui *m_ui;
    Listener *m_listener;
    QMutex m_mutex;
    QVector<std::shared_ptr<Tins::PDU>> m_packets;
    QVector<std::shared_ptr<Field>> m_fields;
    bool m_ascii;
};
