#include "gui.hpp"
#include "ui_gui.h"

namespace
{
inline std::string convert_ip(const uint32_t ip)
{
    return std::to_string(ip & 0xFF000000) + "." + std::to_string(ip & 0x00FF0000) + "." + std::to_string(ip & 0x0000FF00) + "." + std::to_string(ip & 0x000000FF);
}
} // anonymous namespace

Gui::Gui(QWidget *parent) :
    QMainWindow(parent),
    m_ui(new Ui::Gui),
    m_mutex()
{
    m_ui->setupUi(this);
    m_ui->tableWidget->setRowCount(2);
    m_ui->tableWidget->setColumnCount(2);
    m_ui->tableWidget->horizontalHeader()->setStretchLastSection(true);

    QObject::connect(m_ui->listWidget, SIGNAL(currentRowChanged(int)), this, SLOT(show_packet_info(int)));
    /*for (auto i = 0; i < 20; ++i)
        ui->listWidget->addItem(QString::number(i));
    ui->tableWidget->setRowCount(2);
    ui->tableWidget->setColumnCount(2);
    QTableWidgetItem *item00 = new QTableWidgetItem(tr("Source"));
    ui->tableWidget->setItem(0, 0, item00);
    QTableWidgetItem *item01 = new QTableWidgetItem(tr("1234245435"));
    ui->tableWidget->setItem(0, 1, item01);
    QTableWidgetItem *item10 = new QTableWidgetItem(tr("Dst"));
    ui->tableWidget->setItem(1, 0, item10);
    QTableWidgetItem *item11 = new QTableWidgetItem(tr("534643653456"));
    ui->tableWidget->setItem(1, 1, item11);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);*/
}

Gui::~Gui()
{
    delete m_ui;
}

void Gui::on_packet_recieved(const Tins::IP &ip_packet)
{
    m_mutex.lock();
    m_ui->listWidget->addItem(QString::number(ip_packet.protocol()));
    m_packets.push_back(ip_packet);
    m_mutex.unlock();
}

void Gui::show_packet_info(const int index)
{
    Tins::IP &ip_packet = m_packets[index];
    uint8_t version = ip_packet.version();
    uint16_t total_length = ip_packet.tot_len();
    uint32_t source_address = ip_packet.src_addr();
    uint32_t destination_address = ip_packet.dst_addr();

    m_ui->tableWidget->setItem(0, 0, new QTableWidgetItem(tr("Source Address")));
    m_ui->tableWidget->setItem(0, 1, new QTableWidgetItem(tr(convert_ip(source_address).c_str())));
    m_ui->tableWidget->setItem(1, 0, new QTableWidgetItem(tr("Destination Address")));
    m_ui->tableWidget->setItem(1, 1, new QTableWidgetItem(tr(convert_ip(destination_address).c_str())));
}
