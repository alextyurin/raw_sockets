#include <QComboBox>
#include <QDateTime>
#include "listener.hpp"
#include "gui.hpp"
#include "ui_gui.h"

namespace
{
const int packet_limit = 50;

inline QString get_time()
{
    return "[" + QDateTime::currentDateTime().toString() + "]";
}

inline char get_hex_symbol(uint8_t number)
{
    switch (number & 0x0F)
    {
        case 0: return '0'; break;
        case 1: return '1'; break;
        case 2: return '2'; break;
        case 3: return '3'; break;
        case 4: return '4'; break;
        case 5: return '5'; break;
        case 6: return '6'; break;
        case 7: return '7'; break;
        case 8: return '8'; break;
        case 9: return '9'; break;
        case 10: return 'A'; break;
        case 11: return 'B'; break;
        case 12: return 'C'; break;
        case 13: return 'D'; break;
        case 14: return 'E'; break;
        case 15: return 'F'; break;
        default: throw std::runtime_error("Unexpected HEX value " + (number & 0x0F)); break;
    }
}

std::string payload_to_hex(const Tins::RawPDU::payload_type &payload)
{
    std::string res = "";
    for (auto it = payload.begin(); it != payload.end(); ++it)
    {
        res += ::get_hex_symbol(static_cast<uint8_t>(*it));
        res += ::get_hex_symbol(static_cast<uint8_t>(*it) >> 4);
        res += " ";
    }
    return res;
}

std::string payload_to_ascii(const Tins::RawPDU::payload_type &payload)
{
    std::string res = "";
    for (auto it = payload.begin(); it != payload.end(); ++it)
    {
        if (*it != 0)
        {
            res += *it;
        }
        else
        {
            res += " NULL ";
        }
    }
    return res;
}

uint32_t ip_to_int(const QString &ip)
{
    uint32_t res = 0;
    int count = 0;
    QStringList list = ip.split(".");
    for (auto &part : list)
    {
        res += (part.toInt() << 8 * count++);
    }
    return res;
}

} // anonymous namespace

Gui::Gui(const std::string &device, QWidget *parent) :
    QMainWindow(parent),
    m_ui(new Ui::Gui),
    m_ascii(true),
    m_mutex()
{
    m_ui->setupUi(this);
    m_ui->centralWidget->setLayout(m_ui->centralLayout);
    m_ui->radioButton->setChecked(true);
    m_ui->actionStop->setDisabled(true);
    m_ui->tableWidget->setColumnCount(3);
    m_ui->tableWidget->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    clear_table();
    disable_port_form();
    QObject::connect(m_ui->listWidget, SIGNAL(currentRowChanged(int)), this, SLOT(show_packet_info(int)));
    QObject::connect(m_ui->actionStart, SIGNAL(triggered()), this, SLOT(start_listening()));
    QObject::connect(m_ui->actionStop, SIGNAL(triggered()), this, SLOT(stop_listening()));
    QObject::connect(m_ui->actionClear, SIGNAL(triggered()), this, SLOT(clear()));
    QObject::connect(m_ui->actionExit, SIGNAL(triggered()), this, SLOT(exit()));
    QObject::connect(m_ui->radioButton, SIGNAL(clicked()), this, SLOT(ascii_radiobutton_clicked()));
    QObject::connect(m_ui->radioButton_2, SIGNAL(clicked()), this, SLOT(hex_radiobutton_clicked()));
    QObject::connect(m_ui->comboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(combobox_changed(int)));
    m_listener = new Listener(device, this);
}

Gui::~Gui()
{
    delete m_ui;
}

void Gui::stop_listening()
{
    m_listener->stop();
    m_ui->actionStop->setDisabled(true);
    m_ui->actionStart->setDisabled(false);
}

void Gui::start_listening()
{
    m_listener->start();
    m_ui->actionStop->setDisabled(false);
    m_ui->actionStart->setDisabled(true);
}

void Gui::on_packet_recieved(Tins::PDU *pdu)
{
    m_mutex.lock();
    if (check_by_filters(pdu))
    {
        if (m_packets.size() > packet_limit)
        {
            m_packets.pop_front();
            m_ui->listWidget->takeItem(0);
        }
        m_packets.push_back(std::shared_ptr<Tins::PDU>(pdu));
        m_ui->listWidget->addItem(get_title(pdu));
    }
    m_mutex.unlock();
}

bool Gui::check_by_filters(Tins::PDU *pdu)
{
    const auto protocol = m_ui->comboBox->currentIndex();
    bool valid_protocol = false;
    try
    {
        Tins::IP &ip_packet = pdu->rfind_pdu<Tins::IP>();
        if (0 == protocol)
        {
            valid_protocol = true;
        }
        if ((1 == protocol) && (1 == ip_packet.protocol()))
        {
            valid_protocol = true;
            std::cout << "OMG123" << std::endl;
        }
        if ((2 == protocol) && (6 == ip_packet.protocol()))
        {
            valid_protocol = true;
        }
        if ((3 == protocol) && (17 == ip_packet.protocol()))
        {
            valid_protocol = true;
        }
        if (!valid_protocol)
        {
            return false;
        }

        bool valid_address = false;
        if (m_ui->src_ip_edit->text().size() == 0 && m_ui->dst_ip_edit->text().size() == 0)
        {
            valid_address = true;
        }
        if (::ip_to_int(m_ui->src_ip_edit->text()) == ip_packet.src_addr() && m_ui->dst_ip_edit->text().size() == 0)
        {
            valid_address = true;
        }
        if (m_ui->src_ip_edit->text().size() == 0 && ::ip_to_int(m_ui->dst_ip_edit->text()) == ip_packet.dst_addr())
        {
            valid_address = true;
        }
        if (::ip_to_int(m_ui->dst_ip_edit->text()) == ip_packet.dst_addr() && ::ip_to_int(m_ui->src_ip_edit->text()) == ip_packet.src_addr())
        {
            valid_address = true;
        }
        if (!valid_address)
        {
            return false;
        }

        if (0 == protocol || 1 == protocol)
        {
            return true;
        }
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        if (2 == protocol) //TCP
        {
            const Tins::TCP &tcp_packet = pdu->rfind_pdu<Tins::TCP>();
            src_port = tcp_packet.sport();
            dst_port = tcp_packet.dport();
        }
        else if (3 == protocol) //UDP
        {
            const Tins::UDP &udp_packet = pdu->rfind_pdu<Tins::UDP>();
            src_port = udp_packet.sport();
            dst_port = udp_packet.dport();
        }
        bool valid_port = false;
        if (m_ui->src_port_edit->text().size() == 0 && m_ui->dst_port_edit->text().size() == 0)
        {
            valid_port = true;
        }
        if (m_ui->src_port_edit->text().toInt() == ip_packet.src_addr() && m_ui->dst_port_edit->text().size() == 0)
        {
            valid_port = true;
        }
        if (m_ui->dst_port_edit->text().toInt() == ip_packet.dst_addr() && m_ui->src_port_edit->text().size() == 0)
        {
            valid_port = true;
        }
        if (m_ui->dst_port_edit->text().toInt() == ip_packet.dst_addr() && m_ui->src_port_edit->text().toInt() == ip_packet.src_addr())
        {
            valid_port = true;
        }
        return valid_port;
    }
    catch(...){}
    return false;
}

void Gui::show_packet_info(const int index)
{
    if (index >= 0 && index < packet_limit)
    {
        m_mutex.lock();
        clear_table();
        m_ui->plainTextEdit->clear();
        try
        {
            const Tins::IP &ip_packet = m_packets[index]->rfind_pdu<Tins::IP>();
            const Tins::RawPDU* raw = m_packets[index]->find_pdu<Tins::RawPDU>();
            if (raw)
            {
                Tins::RawPDU::payload_type data = raw->payload();
                std::string str = m_ascii ? ::payload_to_ascii(data) : ::payload_to_hex(data);
                m_ui->plainTextEdit->setPlainText(QString(str.c_str()));
            }

            show_ip_packet_info(ip_packet);
            const uint8_t protocol = ip_packet.protocol();
            if (6 == protocol) //TCP
            {
                const Tins::TCP &tcp_packet = m_packets[index]->rfind_pdu<Tins::TCP>();
                show_tcp_packet_info(tcp_packet);
            }
            else if (17 == protocol) //UDP
            {
                const Tins::UDP &udp_packet = m_packets[index]->rfind_pdu<Tins::UDP>();
                show_udp_packet_info(udp_packet);
            }
            else if (1 == protocol)
            {
                show_ip_packet_info(ip_packet);
            }
        }
        catch (Tins::pdu_not_found)
        {
            try
            {
                const Tins::ICMP &icmp_packet = m_packets[index]->rfind_pdu<Tins::ICMP>();
                show_icmp_packet_info(icmp_packet);
            }
            catch (Tins::pdu_not_found)
            {
            }
        }
        m_mutex.unlock();
    }
}

void Gui::show_ip_packet_info(const Tins::IP &packet)
{
    const uint8_t version = packet.version();
    const uint8_t header_length = packet.head_len();
    const uint8_t service_type = packet.tos();
    const uint16_t total_length = packet.tot_len();
    const uint16_t identification = packet.id();
    const uint8_t flags = (packet.frag_off() & 0xE000) >> 13;
    const uint16_t fragment_offset = packet.frag_off() & 0x1FFF;
    const uint8_t ttl = packet.ttl();
    const uint8_t protocol = packet.protocol();
    const uint16_t checksum = packet.checksum();
    const uint32_t source_address = packet.src_addr();
    const uint32_t destination_address = packet.dst_addr();
    //const Tins::options_type &options = packet->options();
    ////////padding

    add_table_row("IP Version", version, 4, Field::Format::DEC);
    add_table_row("Header Length", header_length, 4, Field::Format::DEC);
    add_table_row("Service Type", service_type, 8);
    add_table_row("Total Length", total_length, 16, Field::Format::DEC);
    add_table_row("Identification", identification, 16);
    add_table_row("Flags", flags, 3, Field::Format::BIN);
    add_table_row("Fragment Offset", fragment_offset, 12, Field::Format::DEC);
    add_table_row("TTL", ttl, 8, Field::Format::DEC);
    add_table_row("Protocol", protocol, 8, Field::Format::DEC);
    add_table_row("Checksum", checksum, 16);
    add_table_row("Source Address", source_address, 32, Field::Format::DEC, true);
    add_table_row("Destination Address", destination_address, 32, Field::Format::DEC, true);
    //const Tins::options_type &options = ip_packet.options();
    ////////padding
}

void Gui::show_tcp_packet_info(const Tins::TCP &packet)
{
    const uint16_t source_port = packet.sport();
    const uint16_t destination_port = packet.dport();
    const uint32_t sequence_number = packet.seq();
    const uint32_t acknowledgment_number = packet.ack_seq();
    const uint8_t offset = packet.data_offset() & 0x0F;
    const uint16_t flags = packet.flags() & 0x0FFF;
    const uint16_t window = packet.window();
    const uint16_t checksum = packet.checksum();
    const uint16_t urgent_pointer = packet.urg_ptr();

    add_table_row("Source Port", source_port, 16, Field::Format::DEC);
    add_table_row("Destination Port", destination_port, 16, Field::Format::DEC);
    add_table_row("Sequence Number", sequence_number, 32);
    add_table_row("Acknowledgment Number", acknowledgment_number, 32);
    add_table_row("Offset", offset, 4, Field::Format::DEC);
    add_table_row("TCP Flags", flags, 12, Field::Format::BIN);
    add_table_row("Window", window, 16);
    add_table_row("Checksum", checksum, 16);
    add_table_row("Urgent Pointer", urgent_pointer, 16);
}

void Gui::show_udp_packet_info(const Tins::UDP &packet)
{
    const uint16_t source_port = packet.sport();
    const uint16_t destination_port = packet.dport();
    const uint16_t length = packet.length();
    const uint16_t checksum = packet.checksum();

    add_table_row("Source Port", source_port, 16, Field::Format::DEC);
    add_table_row("Destination Port", destination_port, 16, Field::Format::DEC);
    add_table_row("Length", length, 16, Field::Format::DEC);
    add_table_row("Checksum", checksum, 16);
}

void Gui::show_icmp_packet_info(const Tins::ICMP &packet)
{

}

void Gui::clear_table()
{
    m_fields.clear();
    m_ui->tableWidget->clear();
    m_ui->tableWidget->setRowCount(0);
    m_ui->tableWidget->setHorizontalHeaderLabels(QString("Attribute;Value;Format").split(";"));
}

QString Gui::get_title(Tins::PDU *pdu)
{
    QString protocol_name = "Undefined";
    try
    {
        const Tins::IP &ip_packet = pdu->rfind_pdu<Tins::IP>();
        const uint8_t protocol = ip_packet.protocol();
        protocol_name = (6 == protocol) ? "TCP" : (17 == protocol) ? "UDP" : "IP";
    }
    catch (Tins::pdu_not_found)
    {
        try
        {
            const Tins::ICMP &icmp_packet = pdu->rfind_pdu<Tins::ICMP>();
            protocol_name = "ICMP";
        }
        catch (Tins::pdu_not_found)
        {
        }
    }
    return get_time() + QString(" ") + protocol_name + QString(" packet");
}

void Gui::add_table_row(const std::string &attribute, const uint32_t value, const uint8_t bits, const Field::Format format, const bool is_ip)
{
    m_fields.push_back(std::shared_ptr<Field>(new Field(value, bits, m_ui->tableWidget, attribute, format, is_ip)));
}

void Gui::ascii_radiobutton_clicked()
{
    m_ascii = true;
    show_packet_info(m_ui->listWidget->currentRow());
}

void Gui::hex_radiobutton_clicked()
{
    m_ascii = false;
    show_packet_info(m_ui->listWidget->currentRow());
}

void Gui::combobox_changed(const int index)
{
    switch(index)
    {
        case 0: disable_port_form(); break;
        case 1: disable_port_form(); break;
        case 2: enable_port_form(); break;
        case 3: enable_port_form(); break;
        default: throw std::runtime_error("Unexpected combobox index " + index); break;
    }

}

void Gui::disable_port_form()
{
    m_ui->src_port_label->setVisible(false);
    m_ui->src_port_edit->setVisible(false);
    m_ui->dst_port_label->setVisible(false);
    m_ui->dst_port_edit->setVisible(false);
}

void Gui::enable_port_form()
{
    m_ui->src_port_label->setVisible(true);
    m_ui->src_port_edit->setVisible(true);
    m_ui->dst_port_label->setVisible(true);
    m_ui->dst_port_edit->setVisible(true);
}

void Gui::clear()
{
    clear_table();
    m_ui->listWidget->clear();
    m_packets.clear();
}

void Gui::exit()
{
    QApplication::exit();
}
