# Nom du compilateur
CC = gcc

# Options de compilation
CFLAGS = -Wall -g

# Fichiers source
SRC = src/client.h src/server.h

# Fichiers objets générés à partir des fichiers source
OBJ = $(SRC:.c=.o)

# Nom de l'exécutable
EXEC = bin/secTrans

# Règle principale pour compiler le programme
$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $(EXEC)

# Règle pour compiler les fichiers objets à partir des fichiers sources
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage des fichiers objets et de l'exécutable
clean:
	rm -f $(OBJ) $(EXEC)
