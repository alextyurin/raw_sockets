#pragma once
#include <QThread>
#include <tins/tins.h>
#include "gui.hpp"

class Listener : public QThread
{
    Q_OBJECT
public:
    explicit Listener(const std::string &device, Gui *gui, QObject *parent = 0);
    void run();
    void stop();
private:
    Tins::Sniffer m_sniffer;
    Gui *m_gui;
    bool m_working = false;
};
