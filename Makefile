# Nom du compilateur
CC = gcc

# Options de compilation
CFLAGS = -Wall -g -I./include

# pour openssl
LDFLAGS = -lcrypto

# Répertoires des bibliothèques partagées
LIBDIR = ./libs

# Bibliothèques partagées
LIBS = -lclient -lserver

# Fichiers source
SRC_CLIENT = src/client.c
SRC_SERVER = src/server.c

# Fichiers objets
OBJ_CLIENT = $(SRC_CLIENT:.c=.o)
OBJ_SERVER = $(SRC_SERVER:.c=.o)

# Noms des exécutables
EXEC_CLIENT = bin/secTrans
EXEC_SERVER = bin/server

# Répertoires de sortie
$(shell mkdir -p bin)

# Règle pour le client
$(EXEC_CLIENT): $(OBJ_CLIENT)
	$(CC) $(OBJ_CLIENT) -o $(EXEC_CLIENT) -L$(LIBDIR) $(LIBS) $(LDFLAGS)

# Règle pour le serveur
$(EXEC_SERVER): $(OBJ_SERVER)
	$(CC) $(OBJ_SERVER) -o $(EXEC_SERVER) -L$(LIBDIR) $(LIBS) $(LDFLAGS)

# Règle pour compiler les fichiers objets
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

all: $(EXEC_SERVER) $(EXEC_CLIENT)

# Nettoyage des fichiers objets et des exécutables
clean:
	rm -f $(OBJ_CLIENT) $(OBJ_SERVER) $(EXEC_CLIENT) $(EXEC_SERVER)
