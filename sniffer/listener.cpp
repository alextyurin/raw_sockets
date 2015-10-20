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
        std::unique_ptr<Tins::PDU> pdu(m_sniffer.next_packet());
        try
        {
            m_gui->on_packet_recieved(pdu->rfind_pdu<Tins::IP>());
        }
        catch(Tins::pdu_not_found)
        {
            /*
             *  Listening some other packets -> skip it
             */
        }
    }
}
