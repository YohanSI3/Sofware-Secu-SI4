#ifndef SERVER_H
#define SERVER_H

void startserver(int port);
int stopserver();

/* read message sent by client */
int getmsg(char msg_read[1024]);

#endif
