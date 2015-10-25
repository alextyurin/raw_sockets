#include <QApplication>
#include "gui.hpp"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    Gui gui;
    gui.show();
    return a.exec();
}
