#ifndef SERVER_H
#define SERVER_H

int create_user(const char *username, const char *password);
int login_user(const char *username, const char *password);

void startserver();
int stopserver();

/* read message sent by client */
int getmsg(char msg_read[1024]);

#endif
