#pragma once
#include <QByteArray>
#include <QMainWindow>
#include <tins/tins.h>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    
private slots:
    void on_send_button_clicked();
    void on_radio_button_hex_mode_clicked();
    void on_radio_button_ascii_mode_clicked();

private:
    Ui::MainWindow *m_ui;
    QByteArray m_data;
    Tins::PacketSender m_sender;
    bool m_ascii;
};


