#include <iostream>
#include <QComboBox>
#include "field.hpp"

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

}

Field::Field(const uint32_t value, const uint8_t bits, QTableWidget *table_widget, const std::string &attribute, const Format format, const bool ip_field, QWidget *parent):
    QWidget(parent),
    m_data(value),
    m_bits(bits),
    m_table(table_widget),
    m_is_ip_field(ip_field)
{
    if (format == Format::HEX)
    {
        to_hex();
    }
    else if (format == Format::BIN)
    {
        to_bin();
    }
    else if (format == Format::DEC)
    {
        to_dec();
    }
    else
    {
        throw std::runtime_error("Unexpected format " + format);
    }
    m_table_row = m_table->rowCount();
    m_table->setRowCount(m_table_row + 1);
    m_table->setItem(m_table_row, 0, new QTableWidgetItem(tr(attribute.c_str())));
    m_table->setItem(m_table_row, 1, new QTableWidgetItem(tr(m_value.c_str())));
    QComboBox *combobox = new QComboBox(parent);
    combobox->addItem("Hex");
    combobox->addItem("Bin");
    combobox->addItem("Dec");
    combobox->setCurrentIndex((format == Format::HEX) ? 0 : (format == Format::BIN) ? 1 : 2);
    m_table->setCellWidget(m_table_row, 2, combobox);
    QObject::connect(combobox, SIGNAL(currentIndexChanged(int)), this, SLOT(change_format(int)));
}

uint32_t Field::get_data()
{
    return m_data;
}

void Field::to_hex()
{
    m_value = "";
    if (m_is_ip_field)
    {
        for (auto i = 0; i < 4; ++i)
        {
            uint8_t data = (m_data & (0x000000FF << 8 * i)) >> 8 * i;
            const auto symbols_cnt = 2;
            std::string hex = "";
            for (auto symbol = 0; symbol < symbols_cnt; ++symbol)
            {
                hex = ::get_hex_symbol(data >> 4 * symbol) + hex;
            }
            m_value += hex + ".";
        }
        m_value = m_value.substr(0, m_value.length() - 1);
    }
    else
    {
        const auto symbols_cnt = m_bits / 4;
        for (auto symbol = 0; symbol < symbols_cnt; ++symbol)
        {
            m_value = ::get_hex_symbol(static_cast<uint8_t>((m_data & (0x0000000F << (4 * symbol))) >> 4 * symbol)) + m_value;
        }
    }
}

void Field::to_bin()
{
    m_value = "";
    if (m_is_ip_field)
    {
        for (auto i = 0; i < 4; ++i)
        {
            uint8_t data = (m_data & (0x000000FF << 8 * i)) >> 8 * i;
            std::string bit = "";
            for (auto i = 0; i < 8; ++i)
            {
                bit = std::to_string(data % 2) + bit;
                data /= 2;
            }
            m_value += bit + ".";
        }
        m_value = m_value.substr(0, m_value.length() - 1);
    }
    else
    {
        uint32_t data = m_data;
        for (auto bit = 0; bit < m_bits; ++bit)
        {
            m_value = std::to_string(data % 2) + m_value;
            data /= 2;
        }
    }
}

void Field::to_dec()
{
    if (m_is_ip_field)
    {
        m_value = std::to_string(m_data & 0x000000FF)  + "." + std::to_string((m_data & 0x0000FF00) >> 8) + "." + std::to_string((m_data & 0x00FF0000) >> 16) + "." + std::to_string((m_data & 0xFF000000) >> 24);
    }
    else
    {
        m_value = std::to_string(m_data);
    }
}

std::string Field::to_string()
{
    return m_value;
}

void Field::change_format(const int format)
{
    if (Format::HEX == static_cast<Format>(format))
    {
        to_hex();
    }
    else if (Format::BIN == static_cast<Format>(format))
    {
        to_bin();
    }
    else if (Format::DEC == static_cast<Format>(format))
    {
        to_dec();
    }
    else
    {
        throw std::runtime_error("Unexpected format " + format);
    }
    m_table->setItem(m_table_row, 1, new QTableWidgetItem(tr(m_value.c_str())));
}
