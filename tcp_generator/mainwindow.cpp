#include <QString>
#include <QMessageBox>
#include "mainwindow.hpp"
#include "ui_mainwindow.h"

namespace
{

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

inline uint8_t get_hex_number(char symbol)
{
    switch (symbol)
    {
        case '0': return  0; break;
        case '1': return  1; break;
        case '2': return  2; break;
        case '3': return  3; break;
        case '4': return  4; break;
        case '5': return  5; break;
        case '6': return  6; break;
        case '7': return  7; break;
        case '8': return  8; break;
        case '9': return  9; break;
        case 'A': return 10; break;
        case 'B': return 11; break;
        case 'C': return 12; break;
        case 'D': return 13; break;
        case 'E': return 14; break;
        case 'F': return 15; break;
        default: throw std::runtime_error("Unexpected HEX symbol " + symbol); break;
    }
}

QString convert_to_hex(const QByteArray &data)
{
    QString res = "";
    for (auto &byte : data)
    {
        res += ::get_hex_symbol(static_cast<uint8_t>(byte) >> 4);
        res += ::get_hex_symbol(static_cast<uint8_t>(byte));
        res += " ";
    }
    return res;
}

QString convert_to_ascii(const std::string &data)
{
    QString res = "";
    for (auto it = data.begin(); it != data.end(); it++)
    {
        if (*it == ' ')
        {
            continue;
        }
        res += (get_hex_number(*it) << 4) + get_hex_number(*(it + 1));
        it++;
    }
    return res;
}

}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    m_ui(new Ui::MainWindow),
    m_ascii(true)
{
    m_ui->setupUi(this);
    m_ui->centralWidget->setLayout(m_ui->main);
    m_ui->radio_button_ascii_mode->setChecked(true);
    m_ui->groupBox->setLayout(m_ui->box);
    m_ui->groupBox_2->setLayout(m_ui->box_2);
    m_ui->groupBox_3->setLayout(m_ui->box_3);
}

MainWindow::~MainWindow()
{
    delete m_ui;
}

void MainWindow::on_send_button_clicked()
{
    try
    {
        //ip
        Tins::IP::address_type src_ip(m_ui->src_ip_edit->text().toStdString());
        Tins::IP::address_type dst_ip(m_ui->dst_ip_edit->text().toStdString());
        bool ok = false;
        const uint16_t id = m_ui->id_edit->text().toInt(&ok);
        if (m_ui->id_edit->text().size() != 0 && (!ok || id < 0 || id > 65535))
        {
            throw std::runtime_error("Identification field must be 16 bits");
        }
        const uint16_t offset = m_ui->frag_offset_edit->text().toInt(&ok);
        if (m_ui->frag_offset_edit->text().size() != 0 && (!ok || offset < 0 || offset > 8192))
        {
            throw std::runtime_error("Fragmeng offset field must be 13 bits");
        }
        const uint16_t fragment_offset = (m_ui->x_flag->isChecked() ? 1 << 15 : 0) + (m_ui->d_flag->isChecked() ? 1 << 14 : 0) + (m_ui->m_flag->isChecked() ? 1 << 13 : 0) + m_ui->frag_offset_edit->text().toInt();
        const uint8_t ttl = m_ui->ttl_edit->text().toInt(&ok);
        if (m_ui->ttl_edit->text().size() != 0 && (!ok || ttl < 0 || ttl > 255))
        {
            throw std::runtime_error("TTL field must be 8 bits");
        }
        const uint8_t tos = m_ui->tos_edit->text().toInt(&ok);
        if (m_ui->tos_edit->text().size() != 0 && (!ok || tos < 0 || tos > 255))
        {
            throw std::runtime_error("TOS field must be 8 bits");
        }

        Tins::IP ip_header;
        ip_header.src_addr(src_ip);
        ip_header.dst_addr(dst_ip);
        ip_header.id(id);
        ip_header.frag_off(fragment_offset);
        ip_header.ttl(ttl);
        ip_header.tos(tos);

        //tcp
        const uint16_t src_port = m_ui->src_port_edit->text().toInt(&ok);
        if (!ok || src_port < 0 || src_port > 65535)
        {
            throw std::runtime_error("Source Port field must be 16 bits");
        }
        const uint16_t dst_port = m_ui->dst_port_edit->text().toInt(&ok);
        if (!ok || dst_port < 0 || dst_port > 65535)
        {
            throw std::runtime_error("Destination Port field must be 16 bits");
        }
        const uint32_t seq_num = m_ui->seq_number_edit->text().toInt(&ok);
        if (m_ui->seq_number_edit->text().size() != 0 && (!ok || seq_num < 0 || seq_num > 255))
        {
            throw std::runtime_error("Sequence Number field must be 32 bits");
        }
        const uint32_t ack_num = m_ui->ack_number_edit->text().toInt(&ok);
        if (m_ui->ack_number_edit->text().size() != 0 && (!ok || ack_num < 0 || ack_num > 255))
        {
            throw std::runtime_error("Acknowlegment Number field must be 32 bits");
        }
        const uint16_t tcp_flags =  (m_ui->r1_flag->isChecked() ? 1 << 11 : 0) +
                                    (m_ui->r2_flag->isChecked() ? 1 << 10 : 0) +
                                    (m_ui->r3_flag->isChecked() ? 1 << 9 : 0) +
                                    (m_ui->r4_flag->isChecked() ? 1 << 8 : 0) +
                                    (m_ui->cwr_flag->isChecked() ? 1 << 7 : 0) +
                                    (m_ui->ece_flag->isChecked() ? 1 << 6 : 0) +
                                    (m_ui->urg_flag->isChecked() ? 1 << 5 : 0) +
                                    (m_ui->ack_flag->isChecked() ? 1 << 4 : 0) +
                                    (m_ui->psh_flag->isChecked() ? 1 << 3 : 0) +
                                    (m_ui->rst_flag->isChecked() ? 1 << 2 : 0) +
                                    (m_ui->syn_flag->isChecked() ? 1 << 1 : 0) +
                                    (m_ui->fin_flag->isChecked() ? 1 << 0 : 0);
        const uint8_t data_offset = m_ui->data_offset_edit->text().toInt(&ok);
        if (m_ui->data_offset_edit->text().size() != 0 && (!ok || data_offset < 0 || data_offset > 255))
        {
            throw std::runtime_error("Data Offset field must be 8 bits");
        }
        const uint16_t window_size = m_ui->window_size_edit->text().toInt(&ok);
        if (m_ui->window_size_edit->text().size() != 0 && (!ok || window_size < 0 || window_size > 255))
        {
            throw std::runtime_error("Window Size field must be 8 bits");
        }
        Tins::TCP tcp_header;
        tcp_header.sport(src_port);
        tcp_header.dport(dst_port);
        tcp_header.seq(seq_num);
        tcp_header.ack_seq(ack_num);
        tcp_header.flags(tcp_flags);
        tcp_header.data_offset(data_offset);
        tcp_header.window(window_size);

        Tins::IP packet = ip_header / tcp_header / (m_ascii ? Tins::RawPDU(m_ui->data_edit->toPlainText().toStdString().c_str()) : Tins::RawPDU(convert_to_hex(m_ui->data_edit->toPlainText().toLocal8Bit()).toStdString().c_str()));
        m_sender.send(packet);
    }
    catch (std::runtime_error &e)
    {
        QMessageBox::critical(this, "Error", e.what());
    }
}


void MainWindow::on_radio_button_hex_mode_clicked()
{
    m_ascii = false;
    try
    {
        m_ui->data_edit->setPlainText(convert_to_hex(m_ui->data_edit->toPlainText().toLocal8Bit()));
    }
    catch (std::runtime_error &e)
    {
        QMessageBox::critical(this, "Error", e.what());
    }
}

void MainWindow::on_radio_button_ascii_mode_clicked()
{
    m_ascii = true;
    try
    {
        m_ui->data_edit->setPlainText(convert_to_ascii(m_ui->data_edit->toPlainText().toStdString()));
    }
    catch (std::runtime_error &e)
    {
        QMessageBox::critical(this, "Error", e.what());
    }
}
