TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap -lpthread
SOURCES += main.c

include(deployment.pri)
qtcAddDeployment()

