#pragma once
#include <QWidget>
#include <QTableWidget>

class Field : public QWidget
{
    Q_OBJECT
public:
    enum Format
    {
        HEX = 0,
        BIN = 1,
        DEC = 2
    };
    explicit Field(const uint32_t value, const uint8_t bits, QTableWidget *table_widget, const std::string &attribute, const Format format = Format::HEX, const bool ip_field = false, QWidget *parent = 0);
    uint32_t get_data();
    void to_hex();
    void to_bin();
    void to_dec();
    std::string to_string();
public slots:
    void change_format(const int format);
private:
    std::string m_value;
    uint8_t m_bits;
    QTableWidget *m_table;
    int m_table_row;
    uint32_t m_data;
    bool m_is_ip_field;
};

