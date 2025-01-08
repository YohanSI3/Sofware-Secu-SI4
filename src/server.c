#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include "server.h"

#define MAX_MSG_SIZE 1024
#define DB_FILE "users.db"
#define STORAGE_PATH "./users"
#define SALT "random_salt" // Sel utilisé pour le hachage des mots de passe

// Hacher un mot de passe avec SHA256 et un sel
void hash_password(const char *password, char *hashed_password) { 
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    char salted_password[256];
    snprintf(salted_password, sizeof(salted_password), "%s%s", SALT, password);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salted_password, strlen(salted_password));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&hashed_password[i * 2], "%02x", hash[i]);
    }
    hashed_password[hash_len * 2] = '\0';
}

// Vérifier si un utilisateur existe
int user_exists(const char *username) {
    FILE *db = fopen(DB_FILE, "r");
    if (!db) return 0;

    char line[256];
    while (fgets(line, sizeof(line), db)) {
        char stored_username[128];
        sscanf(line, "%127[^:]", stored_username);
        if (strcmp(username, stored_username) == 0) {
            fclose(db);
            return 1;
        }
    }

    fclose(db);
    return 0;
}

// Créer le dossier utilisateur pour le stockage des fichiers
void create_user_directory(const char *username) {
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), "%s/%s", STORAGE_PATH, username);

    if (mkdir(STORAGE_PATH, 0755) == -1 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier de stockage");
        exit(EXIT_FAILURE);
    }

    if (mkdir(user_dir, 0755) == -1 && errno != EEXIST) {
        perror("Erreur lors de la création du dossier utilisateur");
        exit(EXIT_FAILURE);
    }
}

// Créer un nouvel utilisateur
int create_user(const char *username, const char *password) {
    if (user_exists(username)) {
        printf("Erreur : L'utilisateur '%s' existe déjà.\n", username);
        return 0;
    }

    char hashed_password[65];
    hash_password(password, hashed_password);

    FILE *db = fopen(DB_FILE, "a");
    if (!db) {
        perror("Erreur lors de l'ouverture de la base de données");
        return 0;
    }

    fprintf(db, "%s:%s\n", username, hashed_password);
    fclose(db);

    create_user_directory(username);
    printf("Utilisateur '%s' créé avec succès.\n", username);
    return 1;
}

// Connecter un utilisateur
int login_user(const char *username, const char *password) {
    if (!user_exists(username)) {
        printf("L'utilisateur '%s' n'existe pas.\n Création de l'utilisateur\n", username);
        create_user(username,password);
        sndmsg("SUCCESS",9090);
        return 0;
    }

    char hashed_password[65];
    hash_password(password, hashed_password);

    FILE *db = fopen(DB_FILE, "r");
    if (!db) {
        perror("Erreur lors de l'ouverture de la base de données");
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), db)) {
        char stored_username[128], stored_password[65];
        sscanf(line, "%127[^:]:%64s", stored_username, stored_password);

        if (strcmp(username, stored_username) == 0) {
            fclose(db);
            if (strcmp(hashed_password, stored_password) == 0) {
                printf("Connexion réussie pour '%s'.\n", username);
                sndmsg("SUCCESS",9090);
                return 1;
            } else {
                printf("Erreur : Mot de passe incorrect.\n");
                return 0;
            }
        }
    }

    fclose(db);
    return 0;
}

// Gérer les requêtes envoyées par le client
void handle_request(const char *msg) {
    char command[MAX_MSG_SIZE], username[MAX_MSG_SIZE], password[MAX_MSG_SIZE], filename[MAX_MSG_SIZE];
    char buffer[MAX_MSG_SIZE];

    sscanf(msg, "%[^:]:%[^:]:%s", command, username, password);
    sscanf(msg, "%[^:]:%[^:]:%s", command, username, filename);

    if (strcmp(command, "LOGIN") == 0) {
        if (login_user(username, password)) {
            snprintf(buffer, MAX_MSG_SIZE, "SUCCESS");
        } else {
            snprintf(buffer, MAX_MSG_SIZE, "ERREUR : Mot de passe incorrect.");
        }
    } else if (strcmp(command, "UPLOAD") == 0) {
        char user_dir[256];
        snprintf(user_dir, sizeof(user_dir), "%s/%s", STORAGE_PATH, username);

        // Construire le chemin du fichier
        char file_path[512];
        snprintf(file_path, sizeof(file_path), "%s/%s", user_dir, filename);

        FILE *file = fopen(file_path, "wb");
        if (!file) {
            perror("Erreur lors de l'ouverture du fichier pour écrire les données");
            snprintf(buffer, MAX_MSG_SIZE, "ERREUR : Impossible de sauvegarder %s.", filename);
            sndmsg(buffer, 9090);
            return;
        }

        // Lire les données du fichier
        if (getmsg(buffer) == 0) {
            fwrite(buffer, 1, strlen(buffer), file);
        }
        fclose(file);
        printf("Fichier %s sauvegardé pour l'utilisateur %s.\n", filename, username);
        snprintf(buffer, MAX_MSG_SIZE, "SUCCESS : Fichier %s uploadé.", filename);
        sndmsg(buffer, 9090);

    } else if (strcmp(command, "LIST") == 0) {
        char user_dir[256];
        snprintf(user_dir, sizeof(user_dir), "%s/%s", STORAGE_PATH, username);

        DIR *dir = opendir(user_dir);
        if (!dir) {
            perror("Erreur lors de l'ouverture du dossier utilisateur");
            snprintf(buffer, MAX_MSG_SIZE, "Erreur : Impossible de lister les fichiers.");
            sndmsg(buffer, 9090);
            return;
        }

        struct dirent *entry;
        buffer[0] = '\0'; // Initialise le buffer pour contenir la liste des fichiers

        while ((entry = readdir(dir)) != NULL) {
            // Ignore les dossiers spéciaux "." et ".."
            if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                strncat(buffer, entry->d_name, MAX_MSG_SIZE - strlen(buffer) - 1);
                strncat(buffer, "\n", MAX_MSG_SIZE - strlen(buffer) - 1);
            }
        }

        closedir(dir);

        // Envoie la liste des fichiers au client
        sndmsg(buffer, 9090);
        printf("Liste des fichiers pour l'utilisateur %s envoyée.\n", username);

    } else if (strcmp(command, "DOWNLOAD") == 0) {
        char file_path[256];
        snprintf(file_path, sizeof(file_path), "%s/%s/%s", STORAGE_PATH, username, filename);

        FILE *file = fopen(file_path, "rb");
        if (!file) {
            perror("Erreur lors de l'ouverture du fichier");
            snprintf(buffer, MAX_MSG_SIZE, "ERROR:Le fichier demandé n'existe pas.");
            sndmsg(buffer, 9090);  // Envoyer l'erreur au client
            return;
        }

        // Lire et envoyer le contenu du fichier par fragments
        char file_content[MAX_MSG_SIZE];
        size_t bytes_read;

        while ((bytes_read = fread(file_content, 1, sizeof(file_content), file)) > 0) {
            // Assurez-vous d'envoyer uniquement les données lues
            if (sndmsg(file_content, 9090) < 0) {
                perror("Erreur lors de l'envoi des données au client");
                fclose(file);
                return;
            }
        }

        fclose(file);

        // Signaler la fin de la transmission au client
        snprintf(buffer, MAX_MSG_SIZE, "FINISHED");
        sndmsg(buffer, 9090);
    } else {
        printf("Commande inconnue : %s\n", msg);
    }
}

int main() {
    char buffer[MAX_MSG_SIZE];
    startserver(8080); // Démarre le serveur sur le port 8080
    printf("Serveur en écoute sur le port 8080...\n");

    while (1) {
        if (getmsg(buffer) == 0) {
            printf("%s\n", buffer);
            handle_request(buffer); // Traite chaque requête du client
        }
    }

    stopserver(); // Arrêt du serveur
    return 0;
}
