#include <QApplication>
#include "gui.hpp"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    if (argc != 2)
    {
        std::cout << "Usage: sniffer device. Example: sniffer eth0" << std::endl;
        return 0;
    }
    else
    {
        Gui gui(argv[1]);
        gui.show();
        return a.exec();
    }
}
