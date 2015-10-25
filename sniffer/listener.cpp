#include <memory>
#include "listener.hpp"

Listener::Listener(const std::string &device, Gui *gui, QObject *parent) :
    QThread(parent),
    m_sniffer(device),
    m_gui(gui),
    m_working(false)
{
}

void Listener::run()
{
    m_working = true;
    while(m_working)
    {
        m_gui->on_packet_recieved(m_sniffer.next_packet());
    }
}

void Listener::stop()
{
    m_working = false;
}
