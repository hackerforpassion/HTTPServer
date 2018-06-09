MYSQL_OBJ = $$(mysql_config --cflags)
MYSQL_EXE = $$(mysql_config --libs)
GFLAGS = gcc
CFLAGS = -c  -g -Wall
OFLAGS = -lpthread $(MYSQL_EXE) -o 
IFLAGS = -I ../include/ $(MYSQL_OBJ)
SRC = ../src/
OBJ = ../obj/
BIN = ../bin/
INC = ../include/
All:$(BIN)post.cgi $(BIN)putpost $(BIN)phppost $(BIN)admin $(BIN)server

$(BIN)server:$(OBJ)main.o $(OBJ)send_media.o $(OBJ)sendfile.o $(OBJ)func.o $(OBJ)http_response.o $(OBJ)parse_req.o $(OBJ)read_req.o $(OBJ)chunked.o $(OBJ)anagram_error.o
	$(GFLAGS) $(OFLAGS)  server $(OBJ)main.o  $(OBJ)send_media.o $(OBJ)sendfile.o $(OBJ)func.o $(OBJ)http_response.o $(OBJ)parse_req.o $(OBJ)read_req.o $(OBJ)chunked.o $(OBJ)anagram_error.o
	mv server $(BIN)
$(OBJ)serve.o:$(SRC)serve.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)serve.c
	mv serve.o $(OBJ)
$(OBJ)anagram_error.o:$(SRC)anagram_error.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)anagram_error.c
	mv anagram_error.o $(OBJ)
$(OBJ)serveclient.o:$(SRC)serveclient.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)serveclient.c
	mv serveclient.o $(OBJ)
$(OBJ)send_media.o:$(SRC)send_media.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)send_media.c
	mv send_media.o $(OBJ)
$(OBJ)sendfile.o:$(SRC)sendfile.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)sendfile.c
	mv sendfile.o $(OBJ)
$(OBJ)callphp.o:$(SRC)callphp.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)callphp.c
	mv callphp.o $(OBJ)
$(OBJ)func.o:$(SRC)func.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)func.c
	mv func.o $(OBJ)
$(OBJ)http_response.o:$(SRC)http_response.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)http_response.c
	mv http_response.o $(OBJ)
$(OBJ)parse_req.o:$(SRC)parse_req.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)parse_req.c
	mv parse_req.o $(OBJ)
$(OBJ)chunked.o:$(SRC)chunked.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)chunked.c
	mv chunked.o $(OBJ)
$(OBJ)read_req.o:$(SRC)read_req.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)read_req.c
	mv read_req.o $(OBJ)
$(OBJ)main.o:$(SRC)main.c
	$(GFLAGS) $(CFLAGS) $(IFLAGS) $(SRC)main.c
	mv main.o $(OBJ)
$(BIN)post.cgi:$(SRC)postcgi.c
	$(GFLAGS) $(OFLAGS) post.cgi $(SRC)postcgi.c $(IFLAGS)
	mv post.cgi $(BIN)
$(BIN)putpost:$(SRC)putpost.c
	$(GFLAGS) $(OFLAGS) putpost $(SRC)putpost.c $(IFLAGS)
	mv putpost $(BIN)
$(BIN)phppost:$(SRC)phppost.c
	$(GFLAGS) $(OFLAGS) phppost $(SRC)phppost.c $(IFLAGS)
	mv phppost $(BIN)
$(BIN)admin:$(SRC)admin.c
	$(GFLAGS) $(OFLAGS) admin  $(SRC)admin.c $(IFLAGS)
	mv admin $(BIN)
.PHONY:clean
clean:
	rm $(BIN)server $(BIN)phppost $(BIN)post.cgi $(BIN)putpost $(BIN)admin $(OBJ)*.o
