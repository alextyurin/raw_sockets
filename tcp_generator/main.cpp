#include "mainwindow.hpp"
#include <QApplication>
#include <tins/tins.h>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    return a.exec();
}
