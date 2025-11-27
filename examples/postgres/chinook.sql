/*******************************************************************************
   Chinook Database - Version 1.4
   Script: Chinook_PostgreSql.sql
   Description: Creates and populates the Chinook database.
   DB Server: PostgreSql
   Author: Luis Rocha
   License: http://www.codeplex.com/ChinookDatabase/license
********************************************************************************/


/*******************************************************************************
   Create Tables
********************************************************************************/
CREATE TABLE "Artist"
(
    "ArtistId" INT NOT NULL,
    "Name" VARCHAR(120),
    CONSTRAINT "PK_Artist" PRIMARY KEY  ("ArtistId")
);


/*******************************************************************************
   Populate Tables
********************************************************************************/
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (1, N'AC/DC');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (2, N'Accept');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (3, N'Aerosmith');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (4, N'Alanis Morissette');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (5, N'Alice In Chains');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (6, N'Ant�nio Carlos Jobim');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (7, N'Apocalyptica');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (8, N'Audioslave');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (9, N'BackBeat');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (10, N'Billy Cobham');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (11, N'Black Label Society');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (12, N'Black Sabbath');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (13, N'Body Count');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (14, N'Bruce Dickinson');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (15, N'Buddy Guy');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (16, N'Caetano Veloso');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (17, N'Chico Buarque');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (18, N'Chico Science & Na��o Zumbi');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (19, N'Cidade Negra');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (20, N'Cl�udio Zoli');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (21, N'Various Artists');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (22, N'Led Zeppelin');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (23, N'Frank Zappa & Captain Beefheart');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (24, N'Marcos Valle');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (25, N'Milton Nascimento & Bebeto');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (26, N'Azymuth');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (27, N'Gilberto Gil');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (28, N'Jo�o Gilberto');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (29, N'Bebel Gilberto');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (30, N'Jorge Vercilo');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (31, N'Baby Consuelo');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (32, N'Ney Matogrosso');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (33, N'Luiz Melodia');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (34, N'Nando Reis');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (35, N'Pedro Lu�s & A Parede');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (36, N'O Rappa');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (37, N'Ed Motta');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (38, N'Banda Black Rio');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (39, N'Fernanda Porto');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (40, N'Os Cariocas');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (41, N'Elis Regina');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (42, N'Milton Nascimento');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (43, N'A Cor Do Som');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (44, N'Kid Abelha');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (45, N'Sandra De S�');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (46, N'Jorge Ben');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (47, N'Hermeto Pascoal');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (48, N'Bar�o Vermelho');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (49, N'Edson, DJ Marky & DJ Patife Featuring Fernanda Porto');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (50, N'Metallica');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (51, N'Queen');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (52, N'Kiss');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (53, N'Spyro Gyra');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (54, N'Green Day');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (55, N'David Coverdale');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (56, N'Gonzaguinha');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (57, N'Os Mutantes');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (58, N'Deep Purple');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (59, N'Santana');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (60, N'Santana Feat. Dave Matthews');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (61, N'Santana Feat. Everlast');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (62, N'Santana Feat. Rob Thomas');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (63, N'Santana Feat. Lauryn Hill & Cee-Lo');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (64, N'Santana Feat. The Project G&B');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (65, N'Santana Feat. Man�');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (66, N'Santana Feat. Eagle-Eye Cherry');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (67, N'Santana Feat. Eric Clapton');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (68, N'Miles Davis');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (69, N'Gene Krupa');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (70, N'Toquinho & Vin�cius');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (71, N'Vin�cius De Moraes & Baden Powell');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (72, N'Vin�cius De Moraes');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (73, N'Vin�cius E Qurteto Em Cy');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (74, N'Vin�cius E Odette Lara');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (75, N'Vinicius, Toquinho & Quarteto Em Cy');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (76, N'Creedence Clearwater Revival');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (77, N'C�ssia Eller');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (78, N'Def Leppard');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (79, N'Dennis Chambers');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (80, N'Djavan');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (81, N'Eric Clapton');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (82, N'Faith No More');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (83, N'Falamansa');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (84, N'Foo Fighters');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (85, N'Frank Sinatra');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (86, N'Funk Como Le Gusta');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (87, N'Godsmack');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (88, N'Guns N'' Roses');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (89, N'Incognito');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (90, N'Iron Maiden');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (91, N'James Brown');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (92, N'Jamiroquai');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (93, N'JET');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (94, N'Jimi Hendrix');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (95, N'Joe Satriani');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (96, N'Jota Quest');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (97, N'Jo�o Suplicy');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (98, N'Judas Priest');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (99, N'Legi�o Urbana');
INSERT INTO "Artist" ("ArtistId", "Name") VALUES (100, N'Lenny Kravitz');
