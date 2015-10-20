#include <QApplication>
#include "gui.hpp"
#include "listener.hpp"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Gui gui;
    Listener *listener = new Listener("eth0", &gui);
    listener->start();
    gui.show();
    return a.exec();
}
