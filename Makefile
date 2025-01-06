# Nom du compilateur
CC = gcc

# Options de compilation
CFLAGS = -Wall -g -I./include

#pour openssl
LDFLAGS = -lcrypto

# Fichiers source
SRC = src/client.c src/server.c

# Fichiers objets générés à partir des fichiers source
OBJ = $(SRC:.c=.o)

# Nom de l'exécutable
EXEC = bin/secTrans

# Répertoires des bibliothèques partagées
LIBDIR = ./libs

# Bibliothèques partagées
LIBS = -lclient -lserver

$(shell mkdir -p bin)

# Règle principale pour compiler le programme
$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $(EXEC) -L$(LIBDIR) $(LIBS) $(LDFLAGS)

# Règle pour compiler les fichiers objets à partir des fichiers sources
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage des fichiers objets et de l'exécutable
clean:
	rm -f $(OBJ) $(EXEC)
